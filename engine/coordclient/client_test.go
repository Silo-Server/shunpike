package coordclient_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/types/key"

	"github.com/darthShadow/shunpike/coordination/protocol"
	"github.com/darthShadow/shunpike/engine"
	"github.com/darthShadow/shunpike/engine/coordclient"
)

func tlsFor(srv *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// stub answers registration and netmap requests with one fixed host and records
// what it receives.
type stub struct {
	srv     *httptest.Server
	host    protocol.NodeKey
	netmap  protocol.Netmap
	deny    atomic.Bool
	mu      sync.Mutex
	headers map[string][]http.Header
}

func newStub(t *testing.T) *stub {
	t.Helper()
	s := &stub{host: engine.NodePrivateFromBytes(key.NewNode().Raw32()).Public(), headers: map[string][]http.Header{}}
	var disco protocol.DiscoKey
	if _, err := rand.Read(disco[:]); err != nil {
		t.Fatal(err)
	}
	s.netmap = protocol.Netmap{LeaseSeconds: 10, RefreshSeconds: 3, Hosts: []protocol.Host{{
		Label:     "host",
		NodeKey:   s.host,
		DiscoKey:  disco,
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:9")},
	}}}
	s.netmap.Version = protocol.NetmapVersion(s.netmap)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /registration", func(w http.ResponseWriter, r *http.Request) {
		if !s.admit(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /netmap", func(w http.ResponseWriter, r *http.Request) {
		if !s.admit(w, r) {
			return
		}
		if r.URL.Query().Get("version") == s.netmap.Version {
			select {
			case <-time.After(50 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
		_ = json.NewEncoder(w).Encode(s.netmap)
	})
	s.srv = httptest.NewTLSServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stub) admit(w http.ResponseWriter, r *http.Request) bool {
	s.mu.Lock()
	s.headers[r.URL.Path] = append(s.headers[r.URL.Path], r.Header.Clone())
	s.mu.Unlock()
	if s.deny.Load() {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *stub) seen(path string) []http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]http.Header(nil), s.headers[path]...)
}

// idleEngine returns an engine whose signaling never connects, so a test sees
// only the client's own requests.
func idleEngine(t *testing.T) *engine.Engine {
	t.Helper()
	e, err := engine.New(t.Context(), engine.Config{
		PrivateKey:    engine.NodePrivateFromBytes(key.NewNode().Raw32()),
		StaticNetwork: true,
		Signaling: &engine.Signaling{Dial: func(context.Context, string) (net.Conn, error) {
			return nil, errors.New("signaling disabled")
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := e.Close(); err != nil {
			t.Error(err)
		}
	})
	return e
}

func waitFor(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %v", what, within)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestClientSendsOnlyGivenHeaders(t *testing.T) {
	s := newStub(t)
	e := idleEngine(t)
	given := http.Header{"X-Credential": {"token-1"}}
	err := coordclient.Run(t.Context(), coordclient.Options{
		BaseURL:   s.srv.URL,
		TLSConfig: tlsFor(s.srv),
		Headers:   func(context.Context) (http.Header, error) { return given.Clone(), nil },
	}, e)
	if err != nil {
		t.Fatal(err)
	}
	// The first netmap answered Run; the held follow-up carries ?version=.
	waitFor(t, "second netmap request", 5*time.Second, func() bool { return len(s.seen("/netmap")) >= 2 })
	for _, path := range []string{"/registration", "/netmap"} {
		seen := s.seen(path)
		if len(seen) == 0 {
			t.Fatalf("no %s request", path)
		}
		for _, h := range seen {
			// The HTTP transport frames the registration body with its length.
			h.Del("Content-Length")
			if !reflect.DeepEqual(h, given) {
				t.Fatalf("%s headers = %v, want exactly %v", path, h, given)
			}
		}
	}
}

func TestClientExpiresOn401(t *testing.T) {
	s := newStub(t)
	e := idleEngine(t)
	err := coordclient.Run(t.Context(), coordclient.Options{BaseURL: s.srv.URL, TLSConfig: tlsFor(s.srv)}, e)
	if err != nil {
		t.Fatal(err)
	}
	if !e.IsPeer(s.host) {
		t.Fatal("first netmap did not make the host a peer")
	}
	s.deny.Store(true)
	waitFor(t, "peer expiry after 401", 5*time.Second, func() bool { return !e.IsPeer(s.host) })
}
