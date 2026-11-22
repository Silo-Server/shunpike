// Package testcoord serves the coordination operations over HTTP for module
// tests. It authenticates each request with a signed principal header that the
// test supplies, so it fits no deployment and is never exported outside the
// module.
package testcoord

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"tailscale.com/net/wsconn"

	"github.com/Silo-Server/shunpike/coordination/protocol"
	"github.com/Silo-Server/shunpike/coordination/server"
)

// Header carries a principal signed by Sign.
const Header = "X-Test-Principal"

type claims struct {
	Account string           `json:"account"`
	Device  string           `json:"device"`
	NodeKey protocol.NodeKey `json:"node_key"`
	Expires time.Time        `json:"expires"`
}

func mac(secret []byte, payload string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// Sign returns the Header value that authenticates p to a handler built with
// the same secret.
func Sign(secret []byte, p server.Principal) string {
	payload, err := json.Marshal(claims{string(p.Ref.Account), string(p.Ref.Device), p.NodeKey, p.Expires})
	if err != nil {
		panic(err) // the claims always encode
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return body + "." + base64.RawURLEncoding.EncodeToString(mac(secret, body))
}

func verify(secret []byte, value string) (server.Principal, bool) {
	body, sig, ok := strings.Cut(value, ".")
	if !ok {
		return server.Principal{}, false
	}
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(want, mac(secret, body)) {
		return server.Principal{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return server.Principal{}, false
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return server.Principal{}, false
	}
	return server.Principal{Ref: server.DeviceRef{Account: server.AccountID(c.Account), Device: server.DeviceID(c.Device)}, NodeKey: c.NodeKey, Expires: c.Expires}, true
}

type handler struct {
	secret   []byte
	srv      *server.Server
	region   *server.Region
	accepted func(server.Principal, net.Conn) net.Conn
}

// Option changes how New builds the handler.
type Option func(*handler)

// WithAccepted passes each accepted signaling connection through f before the
// region serves it, so a test can observe the bytes the region reads, at the
// time it reads them. f receives the authorized principal and returns the
// connection the region serves; the region closes that connection, so a
// wrapper must close the one it wraps. A nil f serves the connection as is.
func WithAccepted(f func(p server.Principal, c net.Conn) net.Conn) Option {
	return func(h *handler) { h.accepted = f }
}

// New returns a handler for POST /registration, GET /netmap and the WebSocket
// GET /signal. Each route refuses a request without a valid signed principal
// with 401, and a principal the server does not authorize the same way.
func New(s *server.Server, r *server.Region, secret []byte, opts ...Option) http.Handler {
	h := &handler{secret: secret, srv: s, region: r}
	for _, o := range opts {
		o(h)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /registration", h.registration)
	mux.HandleFunc("GET /netmap", h.netmap)
	mux.HandleFunc("GET /signal", h.signal)
	return mux
}

func (h *handler) principal(w http.ResponseWriter, r *http.Request) (server.Principal, bool) {
	p, ok := verify(h.secret, r.Header.Get(Header))
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
	return p, ok
}

func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, server.ErrUnauthorized):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case errors.Is(err, protocol.ErrTooLarge):
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
	case errors.Is(err, protocol.ErrInvalid):
		http.Error(w, "invalid", http.StatusBadRequest)
	case errors.Is(err, context.Canceled):
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}

func (h *handler) registration(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	reg, err := protocol.DecodeRegistration(r.Body)
	if err != nil {
		fail(w, err)
		return
	}
	if err := h.srv.Register(r.Context(), p, reg); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) netmap(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	m, err := h.srv.Netmap(r.Context(), p, r.URL.Query().Get("version"))
	if err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(m)
}

// socketConn closes the WebSocket immediately, which the region needs when it
// ends a connection at the principal's expiry.
type socketConn struct {
	net.Conn
	socket *websocket.Conn
}

func (c *socketConn) Close() error { return c.socket.CloseNow() }

func (h *handler) signal(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principal(w, r)
	if !ok {
		return
	}
	if _, err := h.srv.Authorize(r.Context(), p); err != nil {
		fail(w, err)
		return
	}
	socket, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"derp"}})
	if err != nil {
		return
	}
	defer func() { _ = socket.CloseNow() }()
	var conn net.Conn = &socketConn{Conn: wsconn.NetConn(r.Context(), socket, websocket.MessageBinary, r.RemoteAddr), socket: socket}
	if h.accepted != nil {
		conn = h.accepted(p, conn)
	}
	_ = h.region.Serve(r.Context(), conn, p)
}
