package engine_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/net/stun/stuntest"
	"tailscale.com/types/key"

	"github.com/Silo-Server/shunpike/coordination/protocol"
	"github.com/Silo-Server/shunpike/coordination/server"
	"github.com/Silo-Server/shunpike/engine"
	"github.com/Silo-Server/shunpike/engine/coordclient"
	"github.com/Silo-Server/shunpike/internal/testcoord"
)

// listedRegionID is the signaling region a lab lists in its netmaps when it
// does not use the default region.
const listedRegionID = 5

// Server timings, short enough for a test and valid together: the refresh
// stays within a third of the lease, and the hold stays below every principal
// lifetime a test uses.
const (
	labLease   = 10 * time.Second
	labRefresh = 3 * time.Second
	labHold    = time.Second
)

// stack is one coordination server with its store, directory and region. A lab
// replaces its stack to model a server that lost its store.
type stack struct {
	srv    *server.Server
	dir    *server.Directory
	region *server.Region
	serve  http.Handler
	cancel context.CancelFunc
}

type logged struct {
	method, path string
	header       http.Header
	status       int // 0 when the handler outlives the request, as for a WebSocket
}

// lab runs a coordination server over HTTPS with a host and devices around it.
type lab struct {
	t       *testing.T
	ctx     context.Context
	secret  []byte
	ts      *httptest.Server
	tls     *tls.Config
	stun    string
	regions []protocol.Region
	home    int // signaling region of every engine
	cur     atomic.Pointer[stack]
	block   atomic.Bool // registration and netmap answer 503
	// budget sets the region's envelope limits at the next reset; the zero value
	// keeps the protocol defaults.
	budget protocol.BudgetLimits
	// tap, when set, wraps the signaling connection each engine dials; self is
	// the dialing engine's node key.
	tap func(self protocol.NodeKey, c net.Conn) net.Conn
	// accept, when set, wraps each signaling connection the region accepts from
	// a device, so a test sees the frames when the region reads them.
	accept func(p server.Principal, c net.Conn) net.Conn
	// maxDevices sets the account's device limit at the next reset; the zero
	// value keeps the server default.
	maxDevices int

	mu  sync.Mutex
	log []logged
	// firstConfirmation is the time of the first netmap response that carried a
	// host confirmation, in Unix nanoseconds.
	firstConfirmation atomic.Int64
}

func newLab(t *testing.T, ctx context.Context, listed bool) *lab {
	t.Helper()
	l := &lab{t: t, ctx: ctx, secret: []byte("test secret")}
	stunAddr, closeSTUN := stuntest.Serve(t)
	t.Cleanup(closeSTUN)
	l.stun = stunAddr.String()
	l.ts = httptest.NewTLSServer(http.HandlerFunc(l.serve))
	t.Cleanup(l.ts.Close)
	l.tls = tlsFor(l.ts)
	if listed {
		l.home = listedRegionID
		l.regions = []protocol.Region{{ID: listedRegionID, Code: "listed", URL: l.ts.URL + "/signal?via=listed"}}
	}
	l.reset()
	t.Cleanup(func() {
		st := l.cur.Load()
		st.cancel()
		_ = st.region.Close()
	})
	return l
}

// wrap passes a signaling connection through the lab's tap, if one is set.
func (l *lab) wrap(self protocol.NodeKey, c net.Conn) net.Conn {
	if l.tap == nil {
		return c
	}
	return l.tap(self, c)
}

// wrapAccepted passes an accepted signaling connection through the lab's accept
// hook, if one is set.
func (l *lab) wrapAccepted(p server.Principal, c net.Conn) net.Conn {
	if l.accept == nil {
		return c
	}
	return l.accept(p, c)
}

// reset swaps in a new server with an empty store.
func (l *lab) reset() {
	l.t.Helper()
	if old := l.cur.Load(); old != nil {
		old.cancel()
		_ = old.region.Close()
	}
	ctx, cancel := context.WithCancel(l.ctx)
	store := server.NewMemoryStore()
	srv, err := server.New(server.Options{Store: store, Regions: l.regions, Lease: labLease, Refresh: labRefresh, Hold: labHold, Reconcile: time.Second, MaxDevicesPerAccount: l.maxDevices})
	if err != nil {
		l.t.Fatal(err)
	}
	dir := server.NewDirectory(store, server.DirectoryOptions{Refresh: time.Second})
	region, err := server.NewRegion(server.RegionOptions{Server: srv, Directory: dir, Budget: protocol.Budget{Limits: l.budget}})
	if err != nil {
		l.t.Fatal(err)
	}
	go func() { _ = srv.Run(ctx) }()
	go func() { _ = dir.Run(ctx) }()
	l.cur.Store(&stack{srv: srv, dir: dir, region: region, serve: testcoord.New(srv, region, l.secret, testcoord.WithAccepted(l.wrapAccepted)), cancel: cancel})
}

type statusWriter struct {
	http.ResponseWriter
	l      *lab
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if bytes.Contains(b, []byte(`"confirmation"`)) {
		w.l.firstConfirmation.CompareAndSwap(0, time.Now().UnixNano())
	}
	return w.ResponseWriter.Write(b)
}

func (l *lab) add(r *http.Request, status int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.log = append(l.log, logged{r.Method, r.URL.Path, r.Header.Clone(), status})
}

func (l *lab) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/signal" {
		l.add(r, 0)
		l.cur.Load().serve.ServeHTTP(w, r)
		return
	}
	if l.block.Load() {
		http.Error(w, "blocked", http.StatusServiceUnavailable)
		l.add(r, http.StatusServiceUnavailable)
		return
	}
	sw := &statusWriter{ResponseWriter: w, l: l, status: http.StatusOK}
	l.cur.Load().serve.ServeHTTP(sw, r)
	l.add(r, sw.status)
}

func (l *lab) count(method, path string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.log {
		if e.method == method && e.path == path {
			n++
		}
	}
	return n
}

func (l *lab) unauthorized() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.log {
		if e.status == http.StatusUnauthorized {
			n++
		}
	}
	return n
}

func (l *lab) requests() []logged {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.log)
}

// credential issues a signed principal for one device on each call.
type credential struct {
	l    *lab
	ref  server.DeviceRef
	node protocol.NodeKey
	mu   sync.Mutex
	ttl  time.Duration
}

func (c *credential) setTTL(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl = d
}

func (c *credential) principal() server.Principal {
	c.mu.Lock()
	defer c.mu.Unlock()
	return server.Principal{Ref: c.ref, NodeKey: c.node, Expires: time.Now().Add(c.ttl)}
}

func (c *credential) headers(context.Context) (http.Header, error) {
	return http.Header{testcoord.Header: {testcoord.Sign(c.l.secret, c.principal())}}, nil
}

// callMeMaybeLog is an engine's logger that keeps the time of the log lines
// magicsock writes about call-me-maybe messages: "announcing new endpoints"
// when the engine's endpoints change, "sent call-me-maybe" when the message
// leaves, and "got call-me-maybe" when the other engine's magicsock reads it.
type callMeMaybeLog struct {
	mu    sync.Mutex
	lines []timedLine
}

type timedLine struct {
	at  time.Time
	msg string
}

func (c *callMeMaybeLog) Enabled(context.Context, slog.Level) bool { return true }

func (c *callMeMaybeLog) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, "call-me-maybe") || strings.Contains(r.Message, "announcing new endpoints") || strings.Contains(r.Message, "magicsock: disco:") {
		c.mu.Lock()
		c.lines = append(c.lines, timedLine{time.Now(), r.Message})
		c.mu.Unlock()
	}
	return nil
}

func (c *callMeMaybeLog) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *callMeMaybeLog) WithGroup(string) slog.Handler      { return c }

// dump logs every kept line, for a failed test.
func (c *callMeMaybeLog) dump(t *testing.T, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.lines {
		t.Logf("%s %s %s", name, l.at.Format("15:04:05.000"), l.msg)
	}
}

// times returns the times of the lines at or after from that contain all of parts.
func (c *callMeMaybeLog) times(from time.Time, parts ...string) []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []time.Time
	for _, l := range c.lines {
		if !l.at.Before(from) && !slices.ContainsFunc(parts, func(p string) bool { return !strings.Contains(l.msg, p) }) {
			out = append(out, l.at)
		}
	}
	return out
}

func newCallMeMaybeLog() (*callMeMaybeLog, *slog.Logger) {
	c := &callMeMaybeLog{}
	return c, slog.New(c)
}

type host struct {
	e    *engine.Engine
	cmm  *callMeMaybeLog
	stop func()
}

// startHost runs a host the way an embedding server does: it publishes the
// host entry and its confirmations, and feeds the directory's devices to its
// engine. The engine's own signaling connection waits for the first entry.
func (l *lab) startHost(t *testing.T, priv engine.NodePrivate) *host {
	t.Helper()
	ctx, cancel := context.WithCancel(l.ctx)
	ready := make(chan struct{})
	cmm, logger := newCallMeMaybeLog()
	e, err := engine.New(ctx, engine.Config{
		PrivateKey:    priv,
		StaticNetwork: true,
		STUNServers:   []string{l.stun},
		Logger:        logger,
		Signaling: &engine.Signaling{RegionID: l.home, Dial: func(c context.Context, _ string) (net.Conn, error) {
			select {
			case <-ready:
			case <-c.Done():
				return nil, c.Err()
			}
			conn, err := l.cur.Load().region.DialLocal(ctx)
			if err != nil {
				return nil, err
			}
			return l.wrap(priv.Public(), conn), nil
		}},
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	e.LogDiscovery()
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.hostLoop(ctx, e, ready)
	}()
	var once sync.Once
	h := &host{e: e, cmm: cmm, stop: func() {
		once.Do(func() {
			cancel()
			<-done
			if err := e.Close(); err != nil {
				t.Error(err)
			}
		})
	}}
	t.Cleanup(h.stop)
	return h
}

func (l *lab) hostLoop(ctx context.Context, e *engine.Engine, ready chan struct{}) {
	confirmed := map[protocol.NodeKey]bool{}
	publish := func() {
		st := l.cur.Load()
		reg, err := e.Registration()
		if err != nil {
			return
		}
		_ = st.srv.PutHost(ctx, server.HostEntry{Label: "host", NodeKey: e.PublicKey(), DiscoKey: e.DiscoKey(), Endpoints: reg.Endpoints})
		live := map[protocol.NodeKey]bool{}
		for _, c := range reg.Confirmations {
			_ = st.srv.SetConfirmation(ctx, "host", c)
			live[c.Peer] = true
		}
		for k := range confirmed {
			if !live[k] {
				_ = st.srv.ClearConfirmation(ctx, "host", k)
			}
		}
		confirmed = live
	}
	feed := func() {
		var peers []engine.Peer
		for _, p := range l.cur.Load().dir.Devices() {
			peers = append(peers, engine.Peer{NodeKey: p.NodeKey, DiscoKey: p.DiscoKey, Endpoints: p.Endpoints, HomeRegion: l.home, Expires: p.Expires})
		}
		_ = e.SetPeers(peers)
	}
	publish()
	close(ready)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.Changed():
			publish()
		case <-l.cur.Load().dir.Changed():
			feed()
		case <-tick.C:
			publish()
		}
	}
}

type device struct {
	e     *engine.Engine
	cmm   *callMeMaybeLog
	cred  *credential
	mu    sync.Mutex
	dials []string
}

func (d *device) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.dials)
}

// newCredential makes a device identity and enrolls it with the current server.
func (l *lab) newCredential(t *testing.T, name string) (engine.NodePrivate, *credential) {
	t.Helper()
	priv := engine.NodePrivateFromBytes(key.NewNode().Raw32())
	c := &credential{l: l, ref: server.DeviceRef{Account: "account", Device: server.DeviceID(name)}, node: priv.Public(), ttl: time.Hour}
	l.enroll(t, c, time.Hour)
	return priv, c
}

func (l *lab) enroll(t *testing.T, c *credential, lease time.Duration) {
	t.Helper()
	if _, err := l.cur.Load().srv.Enroll(l.ctx, c.ref, c.node, nil, time.Now().Add(lease)); err != nil {
		t.Fatal(err)
	}
}

// startDevice runs an engine under the coordination client.
func (l *lab) startDevice(t *testing.T, priv engine.NodePrivate, c *credential) *device {
	t.Helper()
	d := &device{cred: c}
	var logger *slog.Logger
	d.cmm, logger = newCallMeMaybeLog()
	dial := engine.WebSocketDialer(l.tls, c.headers)
	e, err := engine.New(l.ctx, engine.Config{
		PrivateKey:    priv,
		StaticNetwork: true,
		STUNServers:   []string{l.stun},
		Logger:        logger,
		Signaling: &engine.Signaling{RegionID: l.home, Dial: func(ctx context.Context, url string) (net.Conn, error) {
			d.mu.Lock()
			d.dials = append(d.dials, url)
			d.mu.Unlock()
			conn, err := dial(ctx, url)
			if err != nil {
				return nil, err
			}
			return l.wrap(priv.Public(), conn), nil
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
	d.e = e
	e.LogDiscovery()
	err = coordclient.Run(l.ctx, coordclient.Options{BaseURL: l.ts.URL, TLSConfig: l.tls, Headers: c.headers}, e)
	if err != nil {
		t.Fatal(err)
	}
	// The registration is stored; load the device so the host sees it.
	l.cur.Load().dir.Lookup(l.ctx, c.node)
	return d
}

func (l *lab) newDevice(t *testing.T, name string) *device {
	t.Helper()
	priv, c := l.newCredential(t, name)
	return l.startDevice(t, priv, c)
}

// ready waits for two-sided direct readiness between a device and a host.
func (l *lab) ready(t *testing.T, d *device, h *host) {
	t.Helper()
	ctx, cancel := context.WithTimeout(l.ctx, 20*time.Second)
	defer cancel()
	if err := d.e.Ready(ctx, h.e.PublicKey()); err != nil {
		t.Fatal(err)
	}
}

func tlsFor(srv *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
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
