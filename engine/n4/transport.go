package n4

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/darthShadow/shunpike/coordination/protocol"
	"github.com/darthShadow/shunpike/engine"
)

type hostTransport struct {
	key  protocol.NodeKey
	pin  string
	http *http3.Transport
}

// Transport dials resolved node identities using one shared QUIC transport.
// Configure fields before use and keep them unchanged. Resolve is concurrent
// and supplies an already trusted SPKI pin; identity is the node key and pin.
// A Transport must not be copied after use. Close leaves its engine owned by
// the caller. Requests carry their original headers without added credentials.
type Transport struct {
	Engine  *engine.Engine
	Policy  Policy
	Resolve func(host string) (k protocol.NodeKey, spkiSHA256Base64 string, ok bool)

	mu     sync.Mutex
	udp    *quic.Transport
	hosts  map[string]*hostTransport
	closed bool
}

// RoundTrip sends an HTTPS request to a resolved peer. Unresolved hosts fail
// before socket access. A bodyless GET or HEAD whose dial or handshake fails
// retries once only after Resolve supplies a different node key or SPKI pin,
// within the handshake timeout. That includes the re-dial that follows a cached
// connection found dead. A request that fails on an established connection
// returns its error at once. Other requests are never replayed by this transport.
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil || r.URL == nil || r.URL.Scheme != "https" || r.URL.Host == "" || r.URL.User != nil {
		return nil, errors.New("HTTPS peer origin required")
	}
	if err := t.Policy.Validate(); err != nil {
		return nil, err
	}
	if t.Resolve == nil {
		return nil, errors.New("peer resolver required")
	}
	host := r.URL.Hostname()
	k, pin, ok := t.Resolve(host)
	if !ok || k.IsZero() {
		return nil, fmt.Errorf("unresolved peer host %q", host)
	}
	if !validPin(pin) {
		return nil, errors.New("invalid TLS pin")
	}
	res, err := t.roundTrip(r, host, k, pin)
	if _, dialFailed := errors.AsType[*dialError](err); err == nil || !dialFailed || r.Context().Err() != nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) || (r.Body != nil && r.Body != http.NoBody) {
		return res, err
	}
	wait, cancel := context.WithTimeout(r.Context(), t.Policy.QUICConfig().HandshakeIdleTimeout)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		nextKey, nextPin, found := t.Resolve(host)
		if found && !nextKey.IsZero() && (nextKey != k || nextPin != pin) {
			if !validPin(nextPin) {
				return nil, errors.New("invalid TLS pin")
			}
			return t.roundTrip(r, host, nextKey, nextPin)
		}
		t.mu.Lock()
		closed := t.closed
		t.mu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		select {
		case <-wait.Done():
			return nil, err
		case <-tick.C:
		}
	}
}

// dialError marks an error from the dial or the handshake, before a connection
// exists. It keeps the underlying error visible to errors.Is and errors.As.
type dialError struct{ err error }

func (e *dialError) Error() string { return e.err.Error() }
func (e *dialError) Unwrap() error { return e.err }

func validPin(pin string) bool {
	digest, err := base64.StdEncoding.DecodeString(pin)
	return err == nil && len(digest) == sha256.Size
}

func (t *Transport) roundTrip(r *http.Request, host string, k protocol.NodeKey, pin string) (*http.Response, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, net.ErrClosed
	}
	if t.Engine == nil {
		t.mu.Unlock()
		return nil, errors.New("engine required")
	}
	if t.udp == nil {
		t.udp = &quic.Transport{Conn: t.Engine.PacketConn()}
		t.hosts = make(map[string]*hostTransport)
	}
	entry := t.hosts[host]
	if entry == nil || entry.key != k || entry.pin != pin {
		if entry != nil {
			_ = entry.http.Close()
		}
		udp := t.udp
		tlsConfig := PinnedTLS(pin)
		tlsConfig.NextProtos = []string{http3.NextProtoH3}
		tr := &http3.Transport{TLSClientConfig: tlsConfig, QUICConfig: t.Policy.QUICConfig()}
		tr.Dial = func(ctx context.Context, _ string, conf *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			currentKey, currentPin, ok := t.Resolve(host)
			if !ok || currentKey != k || currentPin != pin {
				return nil, &dialError{errors.New("peer identity changed during dial")}
			}
			c, err := udp.Dial(ctx, engine.Addr{Key: k}, conf, qc)
			if err != nil {
				return nil, &dialError{err}
			}
			if err := t.Engine.TrackConnection(c); err != nil {
				_ = c.CloseWithError(0x100, "no peer lease")
				return nil, err
			}
			return c, nil
		}
		entry = &hostTransport{key: k, pin: pin, http: tr}
		t.hosts[host] = entry
	}
	t.mu.Unlock()
	return entry.http.RoundTrip(r)
}

// CloseIdleConnections releases idle HTTP/3 connections for every resolved
// host. Active requests and the shared engine remain available.
func (t *Transport) CloseIdleConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, h := range t.hosts {
		h.http.CloseIdleConnections()
	}
}

// Close closes all host transports and the shared QUIC transport, returning
// their joined errors. It is idempotent and never closes the engine's adapter.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	var err error
	for _, h := range t.hosts {
		err = errors.Join(err, h.http.Close())
	}
	if t.udp != nil {
		err = errors.Join(err, t.udp.Close())
	}
	return err
}
