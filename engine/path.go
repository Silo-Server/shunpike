package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"

	"github.com/darthShadow/shunpike/coordination/protocol"
)

// PathClass is "none", "direct", or "relayed" for the current observed path.
type PathClass string

// PathStatus separates the observed UDP endpoint from permitted relay use.
// JSON fields are class, endpoint, and time_to_direct_ns (nanoseconds).
// TimeToDirect is zero until the first confirmed direct observation.
type PathStatus struct {
	Class        PathClass      `json:"class"`
	Endpoint     netip.AddrPort `json:"endpoint"`
	TimeToDirect time.Duration  `json:"time_to_direct_ns"`
}

func usableEndpoint(a netip.AddrPort) bool {
	return a.IsValid() && a.Port() != 0 && !a.Addr().IsUnspecified() && !a.Addr().IsMulticast() && a.Addr().String() != "127.3.3.40" && a.Addr().String() != "127.3.3.41"
}
func directPong(p *ipnstate.PingResult) bool {
	if p == nil || p.Err != "" || p.PeerRelay != "" || p.DERPRegionID != 0 {
		return false
	}
	a, err := netip.ParseAddrPort(p.Endpoint)
	return err == nil && usableEndpoint(a)
}

// observedPath classifies a status snapshot without taking magicsock locks.
func (e *Engine) observedPath(k key.NodePublic, c *protocol.Confirmation, sb *ipnstate.StatusBuilder) PathStatus {
	s := PathStatus{Class: "none"}
	if p := sb.Status().Peer[k]; p != nil {
		a, err := netip.ParseAddrPort(p.CurAddr)
		if p.PeerRelay == "" && err == nil && usableEndpoint(a) && c != nil && c.Endpoint == a {
			s.Class = "direct"
			s.Endpoint = a
		} else if p.PeerRelay == "" && (err != nil || !usableEndpoint(a)) && p.Active && p.Relay != "" && e.relayedDataAllowed(nodeKey(k)) {
			s.Class = "relayed"
		}
	}
	return s
}

// Path returns the current path for a live peer, or class "none". It never
// stamps TimeToDirect; the direct pong callback owns that timestamp.
func (e *Engine) Path(k protocol.NodeKey) PathStatus {
	sb := &ipnstate.StatusBuilder{WantPeers: true}
	e.disco.UpdateStatus(sb)
	e.mu.Lock()
	defer e.mu.Unlock()
	key := nodePublic(k)
	p, ok := e.peerConfig[key]
	if !ok || e.closed || !time.Now().Before(p.Expires) {
		return PathStatus{Class: "none"}
	}
	c, confirmed := e.confirmedPongLocked(key)
	var evidence *protocol.Confirmation
	if confirmed {
		evidence = &c
	}
	s := e.observedPath(key, evidence, sb)
	d := e.discovery[key]
	if !d.direct.IsZero() {
		s.TimeToDirect = d.direct.Sub(d.first)
	}
	return s
}

// Ready waits for independent direct evidence in both directions. Cancellation,
// engine closure or an absent lease prevents readiness.
func (e *Engine) Ready(ctx context.Context, k protocol.NodeKey) error {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		pingCtx, stop := context.WithTimeout(ctx, 500*time.Millisecond)
		pong, err := e.ping(pingCtx, nodePublic(k))
		stop()
		e.mu.RLock()
		p, ok := e.peerConfig[nodePublic(k)]
		reverse := p.Confirmation
		valid := !e.closed && ok && time.Now().Before(p.Expires) && reverse != nil && reverse.Peer == e.PublicKey() && reverse.DiscoKey == e.DiscoKey() && usableEndpoint(reverse.Endpoint)
		e.mu.RUnlock()
		if err == nil && directPong(pong) && valid && e.Path(k).Class == "direct" {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("two-sided direct readiness: %w", ctx.Err())
		case <-e.ctx.Done():
			return net.ErrClosed
		case <-tick.C:
		}
	}
}
