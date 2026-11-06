package engine

import (
	"net"
	"net/netip"
	"slices"

	"tailscale.com/wgengine/magicsock"

	"github.com/darthShadow/shunpike/coordination/protocol"
)

// Registration returns at most 64 endpoints, preferring STUN and port mappings,
// then IPv4 and IPv6. It includes at most 64 live confirmations, the first by
// peer key, or returns net.ErrClosed.
func (e *Engine) Registration() (protocol.Registration, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return protocol.Registration{}, net.ErrClosed
	}
	r := protocol.Registration{NodeKey: e.PublicKey(), DiscoKey: e.DiscoKey(), Endpoints: []netip.AddrPort{}}
	for _, ep := range magicsock.CapEndpoints(e.endpoints, 64) {
		r.Endpoints = append(r.Endpoints, ep.Addr)
	}
	for k := range e.pongs {
		if c, ok := e.confirmedPongLocked(k); ok {
			r.Confirmations = append(r.Confirmations, c)
		}
	}
	slices.SortFunc(r.Confirmations, func(a, b protocol.Confirmation) int { return slices.Compare(a.Peer[:], b.Peer[:]) })
	// The wire limit is 64 confirmations; keep the first 64 by peer key.
	r.Confirmations = r.Confirmations[:min(len(r.Confirmations), 64)]
	return r, nil
}
