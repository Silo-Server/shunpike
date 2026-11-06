package engine

import (
	"context"
	"errors"
	"time"

	"github.com/quic-go/quic-go"
	"tailscale.com/types/key"
)

// TrackConnection binds c to its live peer lease, closing it on removal or key
// change. It closes and refuses connections with an unknown or expired identity.
func (e *Engine) TrackConnection(c *quic.Conn) error {
	if c == nil {
		return errors.New("nil QUIC connection")
	}
	a, ok := c.RemoteAddr().(Addr)
	if !ok {
		_ = c.CloseWithError(0x100, "unexpected peer address")
		return errors.New("unexpected QUIC peer address")
	}
	k := nodePublic(a.Key)
	e.mu.Lock()
	p, allowed := e.peerConfig[k]
	if !allowed || e.closed || !time.Now().Before(p.Expires) {
		e.mu.Unlock()
		_ = c.CloseWithError(0x100, "no peer lease")
		return errors.New("no peer lease")
	}
	e.connections[c] = k
	e.mu.Unlock()
	context.AfterFunc(c.Context(), func() { e.mu.Lock(); delete(e.connections, c); e.mu.Unlock() })
	return nil
}

func (e *Engine) closePeer(k key.NodePublic) {
	e.mu.Lock()
	var cs []*quic.Conn
	for c, peer := range e.connections {
		if peer == k {
			cs = append(cs, c)
			delete(e.connections, c)
		}
	}
	e.mu.Unlock()
	for _, c := range cs {
		_ = c.CloseWithError(0x100, "lease removed")
	}
}
