package n4

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/darthShadow/shunpike/coordination/protocol"
	"github.com/darthShadow/shunpike/engine"
)

func TestTransportRefusesUnresolvedHost(t *testing.T) {
	// No engine exists: resolving an unknown host must fail before socket use.
	tr := &Transport{Policy: DefaultClientPolicy(), Resolve: func(string) (protocol.NodeKey, string, bool) { return protocol.NodeKey{}, "", false }}
	t.Cleanup(func() {
		if err := tr.Close(); err != nil {
			t.Error(err)
		}
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://unknown.invalid/media", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := tr.RoundTrip(req); err == nil || res != nil {
		t.Fatalf("unresolved request = %v, %v", res, err)
	}
}

// No UDP socket exists even when an incorrect cache comparison reaches Dial.
type failedPacketConn struct{}

func (failedPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (failedPacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, net.ErrClosed }
func (failedPacketConn) Close() error                           { return nil }
func (failedPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (failedPacketConn) SetDeadline(time.Time) error      { return nil }
func (failedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (failedPacketConn) SetWriteDeadline(time.Time) error { return nil }

func failedHTTP3(t *testing.T, dials *atomic.Int32) *http3.Transport {
	t.Helper()
	h := &http3.Transport{Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
		dials.Add(1)
		return nil, errors.New("injected dial failure")
	}}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	return h
}

func cachedFailure(t *testing.T, k protocol.NodeKey, pin string, dials *atomic.Int32) *Transport {
	t.Helper()
	udp := &quic.Transport{Conn: failedPacketConn{}}
	t.Cleanup(func() {
		if err := udp.Close(); err != nil {
			t.Error(err)
		}
	})
	return &Transport{Engine: &engine.Engine{}, Policy: DefaultClientPolicy(), udp: udp, hosts: map[string]*hostTransport{
		"peer.invalid": {key: k, pin: pin, http: failedHTTP3(t, dials)},
	}}
}

func TestTransportSamePinKeepsPool(t *testing.T) {
	k := protocol.NodeKey{1}
	pin := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	var dials, attempts atomic.Int32
	tr := cachedFailure(t, k, pin, &dials)
	entry := tr.hosts["peer.invalid"]
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	resolves := 0
	tr.Resolve = func(string) (protocol.NodeKey, string, bool) {
		resolves++
		// Let one unchanged resolution finish before ending the wait. An
		// incorrect retry on that resolution must reach the network boundary.
		if resolves == 3 {
			cancel()
		}
		return k, strings.Clone(pin), true
	}
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GetConn: func(string) { attempts.Add(1) }})
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://peer.invalid/media", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := tr.RoundTrip(r); err == nil || res != nil {
		t.Fatalf("failed connection returned %v/%v", res, err)
	}
	if tr.hosts["peer.invalid"] != entry {
		t.Fatal("same pin replaced pooled transport")
	}
	if dials.Load() != 1 || attempts.Load() != 1 {
		t.Fatalf("same pin dials=%d attempts=%d, want 1/1", dials.Load(), attempts.Load())
	}
}

func TestTransportRetriesOnlyChangedIdentity(t *testing.T) {
	for _, row := range []struct {
		name, method, change string
		body                 bool
		want                 int32
	}{
		{"get_pin", http.MethodGet, "pin", false, 2},
		{"head_pin", http.MethodHead, "pin", false, 2},
		{"get_key", http.MethodGet, "key", false, 2},
		{"head_key", http.MethodHead, "key", false, 2},
		{"post", http.MethodPost, "pin", false, 1},
		{"get_body", http.MethodGet, "pin", true, 1},
		{"head_body", http.MethodHead, "key", true, 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			k := protocol.NodeKey{1}
			pin := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
			nextKey, nextPin := k, pin
			if row.change == "key" {
				nextKey = protocol.NodeKey{2}
			} else {
				digest := make([]byte, sha256.Size)
				digest[0] = 1
				nextPin = base64.StdEncoding.EncodeToString(digest)
			}
			var dials atomic.Int32
			tr := cachedFailure(t, k, pin, &dials)
			resolves := 0
			tr.Resolve = func(string) (protocol.NodeKey, string, bool) {
				resolves++
				if resolves == 1 {
					return k, pin, true
				}
				// Seed the replacement connection's network failure boundary.
				tr.hosts["peer.invalid"] = &hostTransport{key: nextKey, pin: nextPin, http: failedHTTP3(t, &dials)}
				return nextKey, nextPin, true
			}
			var body io.Reader
			if row.body {
				body = strings.NewReader("payload")
			}
			r, err := http.NewRequestWithContext(t.Context(), row.method, "https://peer.invalid/media", body)
			if err != nil {
				t.Fatal(err)
			}
			if res, err := tr.RoundTrip(r); err == nil || res != nil {
				t.Fatalf("failed connection returned %v/%v", res, err)
			}
			if dials.Load() != row.want {
				t.Fatalf("dial attempts=%d, want %d", dials.Load(), row.want)
			}
		})
	}
}

func TestTransportMalformedPinBeforePackets(t *testing.T) {
	for _, pin := range []string{"!", "", "YQ=="} {
		t.Run(pin, func(t *testing.T) {
			// No engine: malformed pins must fail before adapter access.
			tr := &Transport{Policy: DefaultClientPolicy(), Resolve: func(string) (protocol.NodeKey, string, bool) { return protocol.NodeKey{1}, pin, true }}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://peer.invalid/media", nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := tr.RoundTrip(r)
			if err == nil || !strings.Contains(err.Error(), "pin") || res != nil || tr.udp != nil {
				t.Fatalf("malformed pin result=%v/%v, transport initialized=%v", res, err, tr.udp != nil)
			}
		})
	}
}

func TestPinnedTLSValidation(t *testing.T) {
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("trusted public key")}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	good := base64.StdEncoding.EncodeToString(sum[:])
	for _, row := range []struct {
		name, pin string
		certs     []*x509.Certificate
		valid     bool
	}{
		{"matching", good, []*x509.Certificate{cert}, true},
		{"mismatch", base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)), []*x509.Certificate{cert}, false},
		{"malformed", "!", []*x509.Certificate{cert}, false},
		{"trailing_garbage", good + "!!!!", []*x509.Certificate{cert}, false},
		{"short", "YQ==", []*x509.Certificate{cert}, false},
		{"absent_certificate", good, nil, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			c := PinnedTLS(row.pin)
			if c.MinVersion != tls.VersionTLS13 || c.VerifyConnection == nil {
				t.Fatalf("TLS config = %+v", c)
			}
			if err := c.VerifyConnection(tls.ConnectionState{PeerCertificates: row.certs}); (err == nil) != row.valid {
				t.Fatalf("VerifyConnection() = %v, valid=%v", err, row.valid)
			}
		})
	}
}

func TestPeerFromContextWithoutConnection(t *testing.T) {
	if k, ok := PeerFromContext(context.Background()); ok || !k.IsZero() {
		t.Fatalf("peer = %v/%v, want absent", k, ok)
	}
}
