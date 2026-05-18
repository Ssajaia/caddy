// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package reverseproxy

import (
	"fmt"
	"math"
	weakrand "math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(AdaptiveLatencySelection{})
}

const (
	// adaptiveDefaultAlpha is the default EMA smoothing factor.
	// 0.3 converges within ~10 requests while staying resistant to spikes.
	adaptiveDefaultAlpha = 0.3

	// adaptiveDefaultLatencyNs is the neutral score for upstreams not yet
	// measured, in nanoseconds. All EMA arithmetic stays in nanoseconds
	// throughout to avoid mixed-unit bugs. 100ms = 1e8 ns.
	adaptiveDefaultLatencyNs = float64(100 * time.Millisecond)

	// adaptiveDefaultPenaltyMultiplier scales the neutral baseline to produce
	// the default failure penalty. 5× = 500ms equivalent.
	adaptiveDefaultPenaltyMultiplier = 5.0

	// adaptiveDefaultJitterFactor adds ±10% noise to scores so traffic does
	// not collapse entirely onto the single fastest backend (thundering herd).
	adaptiveDefaultJitterFactor = 0.10
)

// noCopy is a zero-size type that signals to go vet's copylocks analyser
// that the containing struct must not be copied after first use.
// Embed it as the first field so the constraint appears at the top of
// any struct literal that incorrectly tries to copy the type.
//
// See https://github.com/golang/go/issues/8005#issuecomment-190753527
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// LatencyTracker holds EMA latency state for one upstream.
//
// # Placement
//
// LatencyTracker is embedded by value in Host (see hosts.go). Host is
// always heap-allocated via new(Host) and stored in the process-wide
// hosts / dynamicHosts maps, so LatencyTracker state survives config
// reloads alongside passive health-check fail counts.
//
// # Zero value
//
// The zero value is valid and ready to use without any explicit
// initialization call. initialized=false causes scoreNs to return
// adaptiveDefaultLatencyNs until the first sample arrives; applySample
// seeds emaNs from that first sample directly rather than blending it
// into a meaningless zero baseline. Because Host is always allocated
// with new(Host), which zero-initializes all fields, LatencyTracker is
// always in the correct starting state the moment the Host exists.
//
// # Wiring
//
// update and penalty are called from reverseproxy.go only when the
// active selection policy implements LatencyRecorder (enforced by a
// type assertion). If any other policy is active these methods are
// never called; scoreNs returns the neutral default forever and the
// tracker is inert but never wrong.
//
// # Copy safety
//
// Never copy a LatencyTracker or its containing Host. The embedded
// sync.Mutex must not be copied after first use. go vet's copylocks
// analyser enforces this statically via both the Mutex and the noCopy
// sentinel below.
type LatencyTracker struct {
	_           noCopy
	mu          sync.Mutex
	emaNs       float64
	initialized bool
}

// LatencyRecorder is implemented by selection policies that consume
// per-upstream latency measurements. reverseproxy.go type-asserts the
// active SelectionPolicy to this interface after every round-trip, and
// calls recordSuccess or recordFailure only when the assertion succeeds.
//
// This makes the EMA feedback loop an explicit, compiler-checked
// contract rather than an implicit convention that could silently break
// if the call site or the policy type drifts independently.
type LatencyRecorder interface {
	// recordSuccess updates the EMA with a successful round-trip duration.
	recordSuccess(upstream *Upstream, d time.Duration)
	// recordFailure injects a synthetic penalty after a failed round-trip.
	// The measured duration is intentionally not used; it reflects the
	// transport's timeout config, not actual backend latency.
	recordFailure(upstream *Upstream)
}

// update records a successful round-trip duration into the EMA.
// Only called when RoundTrip returns err == nil.
func (t *LatencyTracker) update(d time.Duration, alpha float64) {
	t.applySample(float64(d.Nanoseconds()), alpha)
}

// penalty injects a synthetic heavy sample after a failed request.
//
// The measured round-trip duration is NOT used on failure because it
// reflects the transport's timeout config value rather than actual backend
// latency, and injecting it would corrupt the EMA signal.
// penaltyNs is supplied by the caller so the policy's configured value
// (rather than a hardcoded constant) is always used.
func (t *LatencyTracker) penalty(penaltyNs, alpha float64) {
	t.applySample(penaltyNs, alpha)
}

func (t *LatencyTracker) applySample(ns, alpha float64) {
	if alpha <= 0 || alpha >= 1 {
		alpha = adaptiveDefaultAlpha
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.initialized {
		t.emaNs = ns
		t.initialized = true
		return
	}
	t.emaNs = alpha*ns + (1-alpha)*t.emaNs
}

// scoreNs returns the current EMA in nanoseconds.
// Returns the neutral default for upstreams not yet measured.
func (t *LatencyTracker) scoreNs() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.initialized || t.emaNs <= 0 {
		return adaptiveDefaultLatencyNs
	}
	return t.emaNs
}

// AdaptiveLatencySelection routes each request to the upstream with the
// lowest EMA round-trip latency, with jitter to prevent thundering herd.
//
// # Feedback loop
//
// Select() picks the upstream with the lowest jittered EMA score.
// AdaptiveLatencySelection also implements LatencyRecorder, so
// reverseProxy() in reverseproxy.go calls recordSuccess or recordFailure
// after every round-trip — but only when this policy is actually active
// (enforced via the LatencyRecorder interface assertion). Traffic shifts
// dynamically toward faster backends across requests.
//
// # Failure handling
//
// Failures inject a configurable synthetic penalty (default 500ms) instead
// of the measured round-trip time. This prevents the transport's timeout
// config from corrupting the latency signal. The EMA recovers naturally
// once the backend starts succeeding again.
//
// # EMA persistence across reloads
//
// LatencyTracker is embedded in Host, which lives in the shared hosts /
// dynamicHosts maps. Latency history therefore survives Caddy config
// reloads exactly like passive health-check fail counts do.
//
// # Health and capacity gating
//
// upstream.Available() already incorporates Caddy's passive/active health
// checks, circuit breaker, and max_conns. No duplication is needed here.
//
// # Caddyfile
//
//	reverse_proxy backend1 backend2 backend3 {
//	    lb_policy adaptive_latency
//	}
//
//	# With optional tuning:
//	reverse_proxy backend1 backend2 backend3 {
//	    lb_policy adaptive_latency {
//	        alpha      0.3
//	        penalty_ms 500
//	        jitter_pct 10
//	    }
//	}
type AdaptiveLatencySelection struct {
	// Alpha is the EMA smoothing factor in the open interval (0, 1).
	// Higher values react faster to latency changes but produce noisier
	// scores; lower values are smoother but adapt more slowly.
	// Default: 0.3 (~97% converged after 10 samples).
	Alpha float64 `json:"alpha,omitempty"`

	// PenaltyMs is the synthetic latency sample (in milliseconds) injected
	// into the EMA after a failed request. It should be set to a value that
	// approximates a "bad" round-trip relative to your normal latency range.
	// Using the measured round-trip on failure would corrupt the EMA because
	// that value reflects the transport timeout, not backend latency.
	// Default: 500 (5× the 100ms neutral baseline).
	PenaltyMs float64 `json:"penalty_ms,omitempty"`

	// JitterPct adds uniform random noise of ±JitterPct% to each upstream's
	// score before comparison, preventing all concurrent goroutines from
	// selecting the same backend (thundering herd).
	// Default: 10 (±10%).
	JitterPct float64 `json:"jitter_pct,omitempty"`
}

func (AdaptiveLatencySelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.selection_policies.adaptive_latency",
		New: func() caddy.Module { return new(AdaptiveLatencySelection) },
	}
}

// effectiveAlpha returns the configured smoothing factor, or the default.
func (r AdaptiveLatencySelection) effectiveAlpha() float64 {
	if r.Alpha > 0 && r.Alpha < 1 {
		return r.Alpha
	}
	return adaptiveDefaultAlpha
}

// effectivePenaltyNs returns the configured failure penalty in nanoseconds.
func (r AdaptiveLatencySelection) effectivePenaltyNs() float64 {
	if r.PenaltyMs > 0 {
		return r.PenaltyMs * float64(time.Millisecond)
	}
	return adaptiveDefaultLatencyNs * adaptiveDefaultPenaltyMultiplier
}

// effectiveJitterFactor returns the jitter as a fraction (e.g. 0.10 for 10%).
func (r AdaptiveLatencySelection) effectiveJitterFactor() float64 {
	if r.JitterPct > 0 {
		return r.JitterPct / 100.0
	}
	return adaptiveDefaultJitterFactor
}

// recordSuccess implements LatencyRecorder. It updates the upstream's EMA
// with the measured round-trip duration after a successful request.
func (r AdaptiveLatencySelection) recordSuccess(upstream *Upstream, d time.Duration) {
	upstream.Host.Latency.update(d, r.effectiveAlpha())
}

// recordFailure implements LatencyRecorder. It injects a synthetic penalty
// sample into the upstream's EMA after a failed request. The measured
// round-trip duration is intentionally ignored because on failure it
// reflects the transport's timeout config, not backend latency.
func (r AdaptiveLatencySelection) recordFailure(upstream *Upstream) {
	upstream.Host.Latency.penalty(r.effectivePenaltyNs(), r.effectiveAlpha())
}

// Select returns the upstream with the lowest jittered EMA latency.
//
// Under high concurrency a goroutine may read a score 1–2 updates behind —
// this is expected and harmless; EMA smoothing absorbs single-sample noise.
func (r AdaptiveLatencySelection) Select(pool UpstreamPool, _ *http.Request, _ http.ResponseWriter) *Upstream {
	var best *Upstream
	bestScore := math.MaxFloat64
	jf := r.effectiveJitterFactor()

	for _, upstream := range pool {
		if !upstream.Available() {
			continue
		}

		base := upstream.Host.Latency.scoreNs()

		// Jitter: uniform in [-jf, +jf] as a fraction of the base score.
		// Non-cryptographic PRNG is intentional here — we want speed, not
		// unpredictability.
		jitter := 1.0 + jf*(weakrand.Float64()*2-1) //nolint:gosec
		score := base * jitter

		if best == nil || score < bestScore {
			bestScore = score
			best = upstream
		}
	}
	return best
}

// UnmarshalCaddyfile sets r from Caddyfile tokens.
//
//	lb_policy adaptive_latency [{ alpha N | penalty_ms N | jitter_pct N }]
func (r *AdaptiveLatencySelection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the policy name token
	if d.NextArg() {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		opt := d.Val()
		if !d.NextArg() {
			return d.ArgErr()
		}
		val := d.Val()
		switch opt {
		case "alpha":
			var f float64
			if _, err := fmt.Sscanf(val, "%f", &f); err != nil || f <= 0 || f >= 1 {
				return d.Errf("alpha must be a float in (0, 1), got %q", val)
			}
			r.Alpha = f
		case "penalty_ms":
			var f float64
			if _, err := fmt.Sscanf(val, "%f", &f); err != nil || f <= 0 {
				return d.Errf("penalty_ms must be a positive number, got %q", val)
			}
			r.PenaltyMs = f
		case "jitter_pct":
			var f float64
			if _, err := fmt.Sscanf(val, "%f", &f); err != nil || f < 0 {
				return d.Errf("jitter_pct must be a non-negative number, got %q", val)
			}
			r.JitterPct = f
		default:
			return d.Errf("unknown adaptive_latency option %q", opt)
		}
	}
	return nil
}

var (
	_ Selector              = (*AdaptiveLatencySelection)(nil)
	_ caddyfile.Unmarshaler = (*AdaptiveLatencySelection)(nil)
	_ LatencyRecorder       = (*AdaptiveLatencySelection)(nil)
)