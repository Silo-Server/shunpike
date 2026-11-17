package n4

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/darthShadow/shunpike/coordination/protocol"
	"github.com/darthShadow/shunpike/engine"
)

func testTLS(t *testing.T) (*tls.Config, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"peer.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}, base64.StdEncoding.EncodeToString(sum[:])
}

func privateKey(t *testing.T) engine.NodePrivate {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return engine.NodePrivateFromBytes(b)
}

func testEngine(t *testing.T, k engine.NodePrivate, port uint16) *engine.Engine {
	t.Helper()
	e, err := engine.New(t.Context(), engine.Config{PrivateKey: k, Port: port, StaticNetwork: true, GSO: true})
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

func pair(t *testing.T, a, b *engine.Engine) {
	t.Helper()
	for _, p := range [][2]*engine.Engine{{a, b}, {b, a}} {
		if err := p[0].SetPeers([]engine.Peer{{NodeKey: p[1].PublicKey(), DiscoKey: p[1].DiscoKey(), Endpoints: []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), p[1].LocalPort())}, Expires: time.Now().Add(time.Minute)}}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for a.Path(b.PublicKey()).Class != "direct" || b.Path(a.PublicKey()).Class != "direct" {
		select {
		case <-ctx.Done():
			t.Fatal("direct discovery: ", ctx.Err())
		case <-tick.C:
		}
	}
}

func startServer(t *testing.T, e *engine.Engine, s *http3.Server) func() {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.Serve(e.PacketConn()) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
			if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Error(err)
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func rangeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "fixture", time.Time{}, bytes.NewReader([]byte("0123456789abcdefghijklmnopqrstuvwxyz")))
	})
}

func transportFor(t *testing.T, e *engine.Engine, k protocol.NodeKey, pin string) *Transport {
	t.Helper()
	tr := &Transport{Engine: e, Policy: DefaultClientPolicy(), Resolve: func(host string) (protocol.NodeKey, string, bool) { return k, pin, host == "peer.invalid" }}
	t.Cleanup(func() {
		if err := tr.Close(); err != nil {
			t.Error(err)
		}
	})
	return tr
}

func rangeRequest(t *testing.T, tr http.RoundTripper) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://peer.invalid/media", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Range", "bytes=10-15")
	res, err := tr.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := res.Body.Close(); err != nil {
			t.Error(err)
		}
	})
	return res
}

func checkRange(t *testing.T, res *http.Response) {
	t.Helper()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusPartialContent || string(body) != "abcdef" {
		t.Fatalf("range status=%d body=%q, want 206 abcdef", res.StatusCode, body)
	}
}

func TestHTTP3RangeOverEngine(t *testing.T) {
	a, b := testEngine(t, privateKey(t), 0), testEngine(t, privateKey(t), 0)
	pair(t, a, b)
	tc, pin := testTLS(t)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if k, ok := PeerFromContext(r.Context()); !ok || k != b.PublicKey() {
			t.Errorf("request peer=%v/%v, want %v", k, ok, b.PublicKey())
		}
		if r.Header.Get("Authorization") != "test credential" {
			t.Error("request authorization changed")
		}
		rangeHandler().ServeHTTP(w, r)
	})
	startServer(t, a, NewServer(a, tc, DefaultServerPolicy(), h))
	tr := transportFor(t, b, a.PublicKey(), pin)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://peer.invalid/media", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Range", "bytes=10-15")
	r.Header.Set("Authorization", "test credential")
	res, err := tr.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	checkRange(t, res)
}

func TestTransportSamePinReusesConnection(t *testing.T) {
	a, b := testEngine(t, privateKey(t), 0), testEngine(t, privateKey(t), 0)
	pair(t, a, b)
	tc, pin := testTLS(t)
	s := NewServer(a, tc, DefaultServerPolicy(), rangeHandler())
	admit := s.ConnContext
	var connections atomic.Int32
	s.ConnContext = func(ctx context.Context, c *quic.Conn) context.Context {
		connections.Add(1)
		return admit(ctx, c)
	}
	startServer(t, a, s)
	tr := transportFor(t, b, a.PublicKey(), pin)
	var resolves atomic.Int32
	tr.Resolve = func(string) (protocol.NodeKey, string, bool) {
		resolves.Add(1)
		return a.PublicKey(), strings.Clone(pin), true
	}
	for range 2 {
		res := rangeRequest(t, tr)
		checkRange(t, res)
		if err := res.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if connections.Load() != 1 || resolves.Load() != 3 {
		t.Fatalf("same pin connections=%d resolves=%d, want 1/3", connections.Load(), resolves.Load())
	}
}

func TestServerRefusesNonPeer(t *testing.T) {
	t.Run("connection", func(t *testing.T) {
		a, b := testEngine(t, privateKey(t), 0), testEngine(t, privateKey(t), 0)
		pair(t, a, b)
		tc, pin := testTLS(t)
		var reached atomic.Bool
		s := NewServer(a, tc, DefaultServerPolicy(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }))
		original := s.ConnContext
		seen := make(chan *quic.Conn, 1)
		s.ConnContext = func(ctx context.Context, c *quic.Conn) context.Context {
			// Revoke after adapter admission, before the connection boundary.
			a.Expire()
			ctx = original(ctx, c)
			select {
			case <-c.Context().Done():
			default:
				t.Error("non-peer connection remained open when admission returned")
			}
			seen <- c
			return ctx
		}
		startServer(t, a, s)
		tr := transportFor(t, b, a.PublicKey(), pin)
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://peer.invalid/media", nil)
		if err != nil {
			t.Fatal(err)
		}
		requestDone := make(chan error, 1)
		go func() {
			res, err := tr.RoundTrip(r)
			if res != nil {
				_ = res.Body.Close()
			}
			requestDone <- err
		}()
		observationCtx, stopObserving := context.WithTimeout(t.Context(), 3*time.Second)
		defer stopObserving()
		var c *quic.Conn
		select {
		case c = <-seen:
		case <-observationCtx.Done():
			select {
			case c = <-seen:
			default:
				t.Fatal("connection admission was not exercised")
			}
		}
		// Peer removal can prevent the close packet from reaching the client.
		// Observe local closure before waiting for the request's deadline.
		if c.Context().Err() == nil {
			select {
			case <-c.Context().Done():
			case <-observationCtx.Done():
				if c.Context().Err() == nil {
					t.Fatal("non-peer connection remained open")
				}
			}
		}
		if err := <-requestDone; err == nil {
			t.Fatal("non-peer request succeeded")
		}
		if reached.Load() {
			t.Fatal("non-peer reached handler")
		}
	})
	t.Run("expired_request", func(t *testing.T) {
		a, b := testEngine(t, privateKey(t), 0), testEngine(t, privateKey(t), 0)
		pair(t, a, b)
		tc, pin := testTLS(t)
		contexts := make(chan context.Context, 1)
		s := NewServer(a, tc, DefaultServerPolicy(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { contexts <- r.Context(); rangeHandler().ServeHTTP(w, r) }))
		startServer(t, a, s)
		checkRange(t, rangeRequest(t, transportFor(t, b, a.PublicKey(), pin)))
		ctx := <-contexts
		a.Expire()
		// Tracked connections close on expiry; replay their retained identity
		// directly at the request boundary to prove its independent check.
		r := httptest.NewRequest(http.MethodGet, "https://peer.invalid/media", nil).WithContext(context.WithoutCancel(ctx))
		rec := httptest.NewRecorder()
		s.Handler.ServeHTTP(rec, r)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expired request status=%d, want 403", rec.Code)
		}
	})
}

func TestPinnedTLSRefusesOtherKey(t *testing.T) {
	a, b := testEngine(t, privateKey(t), 0), testEngine(t, privateKey(t), 0)
	pair(t, a, b)
	tc, pin := testTLS(t)
	startServer(t, a, NewServer(a, tc, DefaultServerPolicy(), rangeHandler()))
	udp := &quic.Transport{Conn: b.PacketConn()}
	defer func() {
		if err := udp.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, good := range []bool{false, true} {
		p := pin
		if !good {
			p = base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
		}
		conf := PinnedTLS(p)
		conf.NextProtos = []string{http3.NextProtoH3}
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		c, err := udp.Dial(ctx, engine.Addr{Key: a.PublicKey()}, conf, DefaultClientPolicy().QUICConfig())
		cancel()
		if good && err != nil {
			t.Fatalf("matching pin: %v", err)
		}
		if !good && err == nil {
			t.Fatal("wrong pin accepted")
		}
		if c != nil {
			_ = c.CloseWithError(0, "test complete")
		}
	}
}

func TestTransportRetriesAfterHostRestart(t *testing.T) {
	k := privateKey(t)
	a, b := testEngine(t, k, 0), testEngine(t, privateKey(t), 0)
	pair(t, a, b)
	tc, pin := testTLS(t)
	stop := startServer(t, a, NewServer(a, tc, DefaultServerPolicy(), rangeHandler()))
	failed := make(chan struct{}, 1)
	var current atomic.Value
	current.Store(pin)
	tr := transportFor(t, b, a.PublicKey(), pin)
	tr.Resolve = func(string) (protocol.NodeKey, string, bool) { return k.Public(), current.Load().(string), true }
	checkRange(t, rangeRequest(t, tr))
	tr.CloseIdleConnections()
	// Observe the actual failing dial, without changing the pin verifier.
	prior := tr.hosts["peer.invalid"]
	if err := prior.http.Close(); err != nil {
		t.Fatal(err)
	}
	dial := prior.http.Dial
	prior.http = &http3.Transport{TLSClientConfig: prior.http.TLSClientConfig, QUICConfig: prior.http.QUICConfig, Dial: func(ctx context.Context, addr string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
		c, err := dial(ctx, addr, tc, qc)
		if err != nil {
			select {
			case failed <- struct{}{}:
			default:
			}
		}
		return c, err
	}}
	port, disco := a.LocalPort(), a.DiscoKey()
	stop()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	next := testEngine(t, k, port)
	if next.DiscoKey() == disco {
		t.Fatal("restart retained discovery key")
	}
	pair(t, next, b)
	newTLS, newPin := testTLS(t)
	startServer(t, next, NewServer(next, newTLS, DefaultServerPolicy(), rangeHandler()))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://peer.invalid/media", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Range", "bytes=10-15")
	type result struct {
		response *http.Response
		err      error
	}
	done := make(chan result, 1)
	go func() { res, err := tr.RoundTrip(r); done <- result{res, err} }()
	select {
	case <-failed:
		current.Store(newPin)
	case <-ctx.Done():
		t.Fatal("stale identity was not dialed")
	}
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		defer func() {
			if err := got.response.Body.Close(); err != nil {
				t.Error(err)
			}
		}()
		checkRange(t, got.response)
	case <-ctx.Done():
		t.Fatal("GET did not retry after identity update")
	}
}

// A cached connection to a host that restarted is dead. The transport re-dials
// once, and that dial fails on the old pin: it is a dial failure, so the GET waits
// for the resolver to supply the new pin instead of returning the error at once.
func TestTransportWaitsAfterRedialFailsOnDeadConnection(t *testing.T) {
	k := privateKey(t)
	a, b := testEngine(t, k, 0), testEngine(t, privateKey(t), 0)
	pair(t, a, b)
	tc, pin := testTLS(t)
	stop := startServer(t, a, NewServer(a, tc, DefaultServerPolicy(), rangeHandler()))
	var current atomic.Value
	current.Store(pin)
	tr := transportFor(t, b, a.PublicKey(), pin)
	tr.Resolve = func(string) (protocol.NodeKey, string, bool) { return k.Public(), current.Load().(string), true }
	// The first GET leaves its connection cached; the restart below kills it.
	checkRange(t, rangeRequest(t, tr))
	port := a.LocalPort()
	stop()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	next := testEngine(t, k, port)
	pair(t, next, b)
	newTLS, newPin := testTLS(t)
	startServer(t, next, NewServer(next, newTLS, DefaultServerPolicy(), rangeHandler()))
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://peer.invalid/media", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Range", "bytes=10-15")
	type result struct {
		response *http.Response
		err      error
	}
	done := make(chan result, 1)
	go func() { res, err := tr.RoundTrip(r); done <- result{res, err} }()
	select {
	case got := <-done:
		if got.response != nil {
			_ = got.response.Body.Close()
		}
		t.Fatalf("GET returned (%v) before the resolver supplied the new pin, want it to wait", got.err)
	case <-time.After(time.Second):
	}
	current.Store(newPin)
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		defer func() {
			if err := got.response.Body.Close(); err != nil {
				t.Error(err)
			}
		}()
		checkRange(t, got.response)
	case <-ctx.Done():
		t.Fatal("GET did not retry after the pin changed")
	}
}

// A request that reaches a live connection and fails there is not a key or pin
// problem, so the transport returns its error without waiting for the resolver
// to change.
func TestTransportReturnsConnectedFailureAtOnce(t *testing.T) {
	a, b := testEngine(t, privateKey(t), 0), testEngine(t, privateKey(t), 0)
	pair(t, a, b)
	tc, pin := testTLS(t)
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// HTTP/3 forbids this field; the client refuses the response.
		w.Header().Set("Transfer-Encoding", "chunked")
		_, _ = w.Write([]byte("body"))
	})
	startServer(t, a, NewServer(a, tc, DefaultServerPolicy(), h))
	tr := transportFor(t, b, a.PublicKey(), pin)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://peer.invalid/media", nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res, err := tr.RoundTrip(r)
	elapsed := time.Since(start)
	if err == nil {
		_ = res.Body.Close()
		t.Fatal("response with a forbidden header was accepted")
	}
	if !strings.Contains(err.Error(), "transfer-encoding") {
		t.Fatalf("error = %v, want the refused header", err)
	}
	if elapsed > time.Second {
		t.Fatalf("error took %v, want it returned at once", elapsed)
	}
}
