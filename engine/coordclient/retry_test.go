package coordclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"tailscale.com/types/key"

	"github.com/Silo-Server/shunpike/engine"
)

func TestNetmapRetryWaitsAndKeepsVersion(t *testing.T) {
	const held = "held-version"
	s := time.Second
	for _, row := range []struct {
		name        string
		status      int
		retryAfter  string
		attempts    int
		wantWaits   []time.Duration
		wantVersion string // the version query of every request after the first
	}{
		{"429 backs off exponentially", 429, "", 8, []time.Duration{s, 2 * s, 4 * s, 8 * s, 16 * s, 30 * s, 30 * s, 30 * s}, held},
		{"429 honors Retry-After above the backoff", 429, "7", 3, []time.Duration{7 * s, 7 * s, 7 * s}, held},
		{"429 keeps growing past a small Retry-After", 429, "1", 4, []time.Duration{s, 2 * s, 4 * s, 8 * s}, held},
		{"429 caps Retry-After", 429, "86400", 2, []time.Duration{time.Minute, time.Minute}, held},
		{"429 ignores a malformed Retry-After", 429, "soon", 2, []time.Duration{s, 2 * s}, held},
		{"500 forgets the version", 500, "", 3, []time.Duration{s, 2 * s, 4 * s}, ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			var mu sync.Mutex
			var versions []string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				versions = append(versions, r.URL.Query().Get("version"))
				mu.Unlock()
				if row.retryAfter != "" {
					w.Header().Set("Retry-After", row.retryAfter)
				}
				w.WriteHeader(row.status)
			}))
			defer srv.Close()
			pool := x509.NewCertPool()
			pool.AddCert(srv.Certificate())
			c, err := newClient(Options{BaseURL: srv.URL, TLSConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, newIdleEngine(t))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var waits []time.Duration
			c.sleep = func(ctx context.Context, d time.Duration) bool {
				waits = append(waits, d)
				if len(waits) == row.attempts {
					cancel()
				}
				return ctx.Err() == nil
			}
			c.netmapLoop(ctx, held)
			if !reflect.DeepEqual(waits, row.wantWaits) {
				t.Errorf("waits = %v, want %v", waits, row.wantWaits)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(versions) != row.attempts {
				t.Fatalf("requests = %d, want %d", len(versions), row.attempts)
			}
			for i, v := range versions {
				want := row.wantVersion
				if i == 0 {
					want = held
				}
				if v != want {
					t.Fatalf("request %d version = %q, want %q (all: %v)", i, v, want, versions)
				}
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, row := range []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"12", 12 * time.Second},
		{" 5 ", 5 * time.Second},
		{"-1", 0},
		{"soon", 0},
		{now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second},
		{now.Add(-time.Hour).Format(http.TimeFormat), 0},
	} {
		if got := parseRetryAfter(row.in, now); got != row.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", row.in, got, row.want)
		}
	}
}

// newIdleEngine returns an engine whose signaling never connects.
func newIdleEngine(t *testing.T) *engine.Engine {
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
