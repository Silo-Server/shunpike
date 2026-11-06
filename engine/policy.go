package engine

import (
	"context"
	"net"

	"github.com/quic-go/quic-go"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/magicsock"

	"github.com/darthShadow/shunpike/coordination/protocol"
)

func (e *Engine) relayedDataAllowed(k protocol.NodeKey) bool {
	return e.config.RelayedDataAllowed != nil && e.config.RelayedDataAllowed(k)
}

func (e *Engine) configurePolicy(o *magicsock.Options) {
	o.RelayedDataAllowed = func(k key.NodePublic) bool { return e.relayedDataAllowed(nodeKey(k)) }
	o.QUICDontFragment = dontFragmentControl
	o.DirectPathRecovery = true
	o.DirectPathValidatedFunc = func(k key.NodePublic) {
		n := e.directPathValidated(k)
		o.Logf("engine: path validated peer=%s probe_now=%d", k.ShortString(), n)
	}
	o.MaxCallMeMaybeEndpoints = 64
	if s := e.config.Signaling; s != nil {
		id := e.regionIDLocked(s.RegionID)
		o.SignalingRegions = map[int]magicsock.SignalingRegion{int(id): {Dial: func(ctx context.Context, _ string) (net.Conn, error) {
			e.mu.RLock()
			url := ""
			for _, r := range e.regions {
				if r.ID == s.RegionID {
					url = r.URL
					break
				}
			}
			e.mu.RUnlock()
			return s.Dial(ctx, url)
		}}}
	}
}

func (e *Engine) directPathValidated(k key.NodePublic) int {
	e.mu.RLock()
	var cs []*quic.Conn
	for c, peer := range e.connections {
		if peer == k {
			cs = append(cs, c)
		}
	}
	e.mu.RUnlock()
	for _, c := range cs {
		c.ProbeNow()
	}
	return len(cs)
}
