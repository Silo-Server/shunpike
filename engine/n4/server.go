package n4

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/darthShadow/shunpike/coordination/protocol"
	"github.com/darthShadow/shunpike/engine"
)

type peerContextKey struct{}

// PeerFromContext returns the admitted connection's node key. Contexts outside
// NewServer return a zero key and false; callers still check current authority.
func PeerFromContext(ctx context.Context) (protocol.NodeKey, bool) {
	k, ok := ctx.Value(peerContextKey{}).(protocol.NodeKey)
	return k, ok
}

// NewServer constructs HTTP/3 admission around e and h. Serve it with
// srv.Serve(e.PacketConn()). Connections without live leases close immediately;
// each request checks the lease again and returns 403 after revocation.
// Validate p first. An invalid policy closes connections and refuses requests.
func NewServer(e *engine.Engine, tlsConfig *tls.Config, p Policy, h http.Handler) *http3.Server {
	policyErr := p.Validate()
	return &http3.Server{TLSConfig: tlsConfig, QUICConfig: p.QUICConfig(), ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
		if policyErr != nil {
			_ = c.CloseWithError(0x100, "invalid policy")
			return ctx
		}
		if err := e.TrackConnection(c); err != nil {
			_ = c.CloseWithError(0x100, "no peer lease")
			return ctx
		}
		a, ok := c.RemoteAddr().(engine.Addr)
		if !ok {
			_ = c.CloseWithError(0x100, "unexpected peer address")
			return ctx
		}
		return context.WithValue(ctx, peerContextKey{}, a.Key)
	}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k, ok := PeerFromContext(r.Context())
		if policyErr != nil || !ok || !e.IsPeer(k) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})}
}
