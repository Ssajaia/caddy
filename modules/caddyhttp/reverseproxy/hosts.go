// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package reverseproxy

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// UpstreamPool is a collection of upstreams.
type UpstreamPool []*Upstream

// Upstream bridges this proxy's configuration to the
// state of the backend host it is correlated with.
// Upstream values must not be copied.
type Upstream struct {
	*Host `json:"-"`

	// The [network address](/docs/conventions#network-addresses)
	// to dial to connect to the upstream. Must represent precisely
	// one socket (i.e. no port ranges). A valid network address
	// either has a host and port or is a unix socket address.
	//
	// Placeholders may be used to make the upstream dynamic, but be
	// aware of the health check implications of this: a single
	// upstream that represents numerous (perhaps arbitrary) backends
	// can be considered down if one or enough of the arbitrary
	// backends is down. Also be aware of open proxy vulnerabilities.
	Dial string `json:"dial,omitempty"`

	// The maximum number of simultaneous requests to allow to
	// this upstream. If set, overrides the global passive health
	// check UnhealthyRequestCount value.
	MaxRequests int `json:"max_requests,omitempty"`

	activeHealthCheckPort     int
	activeHealthCheckUpstream string
	healthCheckPolicy         *PassiveHealthChecks
	cb                        CircuitBreaker
	unhealthy                 atomic.Int32 // status from active health checker
}

// (pointer receiver necessary to avoid a race condition, since
// copying the Upstream reads the 'unhealthy' field which is
// accessed atomically)
func (u *Upstream) String() string { return u.Dial }

// Available returns true if the remote host
// is available to receive requests. This is
// the method that should be used by selection
// policies, etc. to determine if a backend
// should be able to be sent a request.
func (u *Upstream) Available() bool {
	return u.Healthy() && !u.Full()
}

// Healthy returns true if the remote host
// is currently known to be healthy or "up".
// It consults the circuit breaker, if any.
func (u *Upstream) Healthy() bool {
	healthy := u.healthy()
	if healthy && u.healthCheckPolicy != nil {
		healthy = u.Host.Fails() < u.healthCheckPolicy.MaxFails
	}
	if healthy && u.cb != nil {
		healthy = u.cb.OK()
	}
	return healthy
}

// Full returns true if the remote host
// cannot receive more requests at this time.
func (u *Upstream) Full() bool {
	return u.MaxRequests > 0 && u.Host.NumRequests() >= u.MaxRequests
}

// fillDialInfo returns a filled DialInfo for upstream u, using the request
// context. Note that the returned value is not a pointer.
func (u *Upstream) fillDialInfo(repl *caddy.Replacer) (DialInfo, error) {
	var addr caddy.NetworkAddress

	// use provided dial address
	var err error
	dial := repl.ReplaceAll(u.Dial, "")
	addr, err = caddy.ParseNetworkAddress(dial)
	if err != nil {
		return DialInfo{}, fmt.Errorf("upstream %s: invalid dial address %s: %v", u.Dial, dial, err)
	}
	if numPorts := addr.PortRangeSize(); numPorts != 1 {
		return DialInfo{}, fmt.Errorf("upstream %s: dial address must represent precisely one socket: %s represents %d",
			u.Dial, dial, numPorts)
	}
	return DialInfo{
		Upstream: u,
		Network:  addr.Network,
		Address:  addr.JoinHostPort(0),
		Host:     addr.Host,
		Port:     strconv.Itoa(int(addr.StartPort)),
	}, nil
}

// fillHost associates u with its shared Host entry from the static hosts
// pool, creating one if this is the first time this address is seen.
// The Host (and its embedded LatencyTracker) persists across config reloads
// because it lives in the process-wide hosts sync.Map.
func (u *Upstream) fillHost() {
	host := new(Host)
	existingHost, loaded := hosts.LoadOrStore(u.String(), host)
	if loaded {
		host = existingHost.(*Host)
	}
	u.Host = host
}

// fillDynamicHost is like fillHost, but stores the host in the separate
// dynamicHosts map rather than the reference-counted UsagePool. Dynamic
// hosts are not reference-counted; instead, they are retained as long as
// they are actively seen and are evicted by a background cleanup goroutine
// after dynamicHostIdleExpiry of inactivity. This preserves health state
// (e.g. passive fail counts and EMA latency) across sequential requests.
func (u *Upstream) fillDynamicHost() {
	dynamicHostsMu.Lock()
	entry, ok := dynamicHosts[u.String()]
	if ok {
		entry.lastSeen = time.Now()
		dynamicHosts[u.String()] = entry
		u.Host = entry.host
	} else {
		h := new(Host)
		dynamicHosts[u.String()] = dynamicHostEntry{host: h, lastSeen: time.Now()}
		u.Host = h
	}
	dynamicHostsMu.Unlock()
}

// Host is the basic, in-memory representation of the state of a remote
// host. Its fields are accessed atomically and Host values must not be
// copied.
type Host struct {
	numRequests int64 // accessed atomically; must be 64-bit aligned on 32-bit systems
	fails       int64 // accessed atomically; must be 64-bit aligned on 32-bit systems
	unhealthy   int32 // accessed atomically

	// Latency tracks the exponential moving average round-trip time for
	// this host. It is embedded here (rather than on Upstream) so that
	// EMA history survives config reloads alongside other host state.
	// Used by the adaptive_latency selection policy; ignored otherwise.
	// Never copy Host — LatencyTracker embeds a sync.Mutex.
	Latency LatencyTracker
}

// NumRequests returns the number of active requests to the upstream.
func (h *Host) NumRequests() int {
	return int(atomic.LoadInt64(&h.numRequests))
}

// Fails returns the number of recent failures with the upstream.
func (h *Host) Fails() int {
	return int(atomic.LoadInt64(&h.fails))
}

func (h *Host) healthy() bool {
	return atomic.LoadInt32(&h.unhealthy) == 0
}

func (h *Host) setHealthy(healthy bool) bool {
	var unhealthy, compare int32 = 1, 0
	if healthy {
		unhealthy, compare = 0, 1
	}
	return atomic.CompareAndSwapInt32(&h.unhealthy, compare, unhealthy)
}

func (h *Host) countRequest(delta int) error {
	if delta < 0 {
		// do not let it go below zero
		for {
			curr := atomic.LoadInt64(&h.numRequests)
			if curr == 0 {
				return nil
			}
			if next := curr + int64(delta); next >= 0 {
				if atomic.CompareAndSwapInt64(&h.numRequests, curr, next) {
					return nil
				}
			}
		}
	}
	atomic.AddInt64(&h.numRequests, int64(delta))
	return nil
}

func (h *Host) countFail(delta int) error {
	if delta < 0 {
		// do not let it go below zero
		for {
			curr := atomic.LoadInt64(&h.fails)
			if curr == 0 {
				return nil
			}
			if next := curr + int64(delta); next >= 0 {
				if atomic.CompareAndSwapInt64(&h.fails, curr, next) {
					return nil
				}
			}
		}
	}
	atomic.AddInt64(&h.fails, int64(delta))
	return nil
}

// DialInfo contains information needed to dial a
// connection to an upstream host.
type DialInfo struct {
	// Upstream is the Upstream associated with
	// this DialInfo. It may be nil.
	Upstream *Upstream

	// The network to use. This should be one of
	// the values that is accepted by net.Dial:
	// https://golang.org/pkg/net/#Dial
	Network string

	// The address to dial. Follows the format
	// accepted by net.Dial:
	// https://golang.org/pkg/net/#Dial
	// but without the network prefix.
	Address string

	// Host and Port are components of Address.
	Host, Port string
}

// String returns the Caddy network address form
// by joining the network and address with a forward slash.
func (di DialInfo) String() string {
	if di.Network == "" {
		return di.Address
	}
	return di.Network + "/" + di.Address
}

// GetDialInfo gets the DialInfo from the context, if any.
func GetDialInfo(ctx context.Context) (DialInfo, bool) {
	di, ok := ctx.Value(dialInfoVarKey).(DialInfo)
	return di, ok
}

// countFailure is used with passive health checks. It
// remembers 1 failure for upstream for the configured
// duration. If the number of failures exceeds the
// limit, the host is marked as down.
func (h *Handler) countFailure(upstream *Upstream) {
	// only count failures if passive health checking is enabled
	// and the upstream host is healthy (already marked down? skip)
	if h.HealthChecks == nil || h.HealthChecks.Passive == nil {
		return
	}
	passiveHC := h.HealthChecks.Passive
	if passiveHC.MaxFails == 0 {
		return
	}

	// count the fail
	err := upstream.Host.countFail(1)
	if err != nil {
		h.logger.Error("could not count failure", zap.Error(err))
		return
	}

	// if we've failed too many times recently, mark the host as down
	if upstream.Host.Fails() >= passiveHC.MaxFails {
		changed := upstream.Host.setHealthy(false)
		if changed {
			h.logger.Warn("upstream marked as unhealthy",
				zap.String("upstream", upstream.String()),
				zap.Int("max_fails", passiveHC.MaxFails),
			)
			if h.events != nil {
				h.events.Emit(h.ctx, "unhealthy", map[string]any{
					"upstream": upstream.Dial,
				})
			}
		}
	}

	// schedule removal of this failure after FailDuration
	if passiveHC.FailDuration == 0 {
		return
	}
	go func(host *Host) {
		timer := time.NewTimer(time.Duration(passiveHC.FailDuration))
		select {
		case <-h.ctx.Done():
			timer.Stop()
		case <-timer.C:
			err := host.countFail(-1)
			if err != nil {
				h.logger.Error("could not count failure", zap.Error(err))
			}
		}
	}(upstream.Host)
}

// activeHealthChecker runs active health checks on a
// regular basis until ctx is cancelled.
func (h *Handler) activeHealthChecker() {
	defer func() {
		if err := recover(); err != nil {
			h.logger.Error("panic in active health checker", zap.Any("error", err))
		}
	}()
	ticker := time.NewTicker(time.Duration(h.HealthChecks.Active.Interval))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.doActiveHealthCheckForAllHosts()
		case <-h.ctx.Done():
			return
		}
	}
}

// doActiveHealthCheckForAllHosts performs active health checks
// for all upstream hosts.
func (h *Handler) doActiveHealthCheckForAllHosts() {
	for _, upstream := range h.Upstreams {
		go func(upstream *Upstream) {
			defer func() {
				if err := recover(); err != nil {
					h.logger.Error("panic in active health check", zap.Any("error", err))
				}
			}()

			hostAddr := upstream.activeHealthCheckUpstream
			if hostAddr == "" {
				hostAddr = upstream.Dial
			}
			err := h.doActiveHealthCheck(DialInfo{
				Upstream: upstream,
				Network:  "",
				Address:  hostAddr,
			}, hostAddr, upstream.Host)
			if err != nil {
				h.logger.Error("active health check failed",
					zap.String("upstream", upstream.String()),
					zap.Error(err))
			}
		}(upstream)
	}
}

// dynamicHostEntry is an entry in the dynamicHosts map.
type dynamicHostEntry struct {
	host     *Host
	lastSeen time.Time
}

// dynamicHostIdleExpiry is how long a dynamic host can be
// idle (not seen in a request) before it is evicted.
const dynamicHostIdleExpiry = 10 * time.Minute

// hosts stores the set of all upstream host states, keyed
// by upstream address. It is used for static upstreams.
//
// Memory bounds: entries are added in fillHost (called from
// provisionUpstream during Provision) and removed in Handler.Cleanup
// (called by Caddy when the handler is torn down on config reload or
// shutdown). The map therefore holds at most one entry per unique
// upstream address across all active reverse_proxy handler instances.
// There is no background eviction goroutine because Cleanup is the
// authoritative eviction point for static hosts.
var hosts sync.Map

// dynamicHosts stores the set of all upstream host states for
// dynamic upstreams.
//
// Why two maps?
//
// Static upstreams (hosts) are reference-counted by Caddy's module
// lifecycle: Provision adds them, Cleanup removes them. This works
// because the set of static upstreams is known at config load time.
//
// Dynamic upstreams are resolved per-request via GetUpstreams and may
// return a different set on every call. Reference-counting is not
// viable because there is no "unprovision" event for individual dynamic
// entries. Instead, dynamic hosts are retained as long as they are
// actively seen (lastSeen updated each time fillDynamicHost runs) and
// evicted by the background goroutine in init() after
// dynamicHostIdleExpiry of inactivity.
//
// Both maps hold *Host pointers, which are never copied, satisfying the
// no-copy invariant enforced by the embedded sync.Mutex and noCopy fields.
var (
	dynamicHosts   = make(map[string]dynamicHostEntry)
	dynamicHostsMu sync.Mutex
)

func init() {
	// periodically clean up idle dynamic hosts
	go func() {
		ticker := time.NewTicker(dynamicHostIdleExpiry)
		defer ticker.Stop()
		for range ticker.C {
			dynamicHostsMu.Lock()
			for addr, entry := range dynamicHosts {
				if time.Since(entry.lastSeen) > dynamicHostIdleExpiry {
					delete(dynamicHosts, addr)
				}
			}
			dynamicHostsMu.Unlock()
		}
	}()
}

// dialInfoVarKey is the key used to store DialInfo in a request context.
const dialInfoVarKey = caddyhttp.VarKey("reverse_proxy_dial_info")

// netipAddr converts addr to a netip.Addr, if possible, with zone.
func netipAddr(addr string) (netip.Addr, bool) {
	ipAddr, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}, false
	}
	return ipAddr, true
}