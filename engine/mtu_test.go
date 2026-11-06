package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"crypto/tls"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

func TestAdapterPacketLimit(t *testing.T) {
	a, b, _ := engines(t)
	// 1500 - IPv6(40) - UDP(8). Direct magicsock strips its 8-byte headroom.
	payload := bytes.Repeat([]byte{0x40}, 1452)
	if n, err := a.packets.WriteTo(payload, Addr{Key: b.PublicKey()}); err != nil || n != len(payload) {
		t.Fatalf("limit write=%d, %v; want %d, nil", n, err, len(payload))
	}
	if err := b.PacketConn().SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 1500)
	n, _, err := b.PacketConn().ReadFrom(got)
	if err != nil || !bytes.Equal(got[:n], payload) {
		t.Fatalf("limit packet intact=%t, length=%d, err=%v", bytes.Equal(got[:n], payload), n, err)
	}
	if n, err := a.packets.WriteTo(append(payload, 0), Addr{Key: b.PublicKey()}); n != 0 || !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("oversize write=%d, %v; want 0, EMSGSIZE", n, err)
	}
}

// This boundary models either a local EMSGSIZE or a remote link silently
// discarding oversized datagrams, while retaining real QUIC and magicsock I/O.
type smallerMTUConn struct {
	*packetConn
	limit       int
	silent      bool
	refused     atomic.Uint64
	acceptedMax atomic.Uint64
}

func (p *smallerMTUConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) > p.limit {
		p.refused.Add(1)
		if p.silent {
			return len(b), nil
		}
		return 0, syscall.EMSGSIZE
	}
	n, err := p.packetConn.WriteTo(b, addr)
	if err == nil {
		for old := p.acceptedMax.Load(); uint64(n) > old; old = p.acceptedMax.Load() {
			if p.acceptedMax.CompareAndSwap(old, uint64(n)) {
				break
			}
		}
	}
	return n, err
}

func TestAdapterPathMTUDiscovery(t *testing.T) {
	for _, mode := range []string{"1500-link", "smaller-link-EMSGSIZE", "smaller-link-loss"} {
		t.Run(mode, func(t *testing.T) {
			a, b, tlsConfig := engines(t)
			// A rebind must install DF on the replacement sockets too.
			for _, e := range []*Engine{a, b} {
				for _, rebind := range []bool{false, true} {
					if rebind {
						e.magic.Rebind()
					}
					df, err := e.magic.DontFragSetting()
					if err != nil || !df {
						t.Errorf("DF after rebind=%t: %t, %v", rebind, df, err)
					}
				}
			}
			pair(t, a, b)
			limit := 1452
			if mode != "1500-link" {
				limit = 1252
			}
			ap := &smallerMTUConn{packetConn: a.packets, limit: limit, silent: mode == "smaller-link-loss"}
			var trace Trace
			qc := testQUICConfig(false)
			qc.Tracer = trace.New
			payload := bytes.Repeat([]byte("QUIC fixture "), 4096)
			srv := &http3.Server{TLSConfig: tlsConfig, QUICConfig: qc, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) })}
			done := make(chan error, 1)
			go func() { done <- srv.Serve(ap) }()
			defer func() {
				_ = srv.Close()
				if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
					t.Errorf("serve shutdown: %v", err)
				}
			}()
			rt := testRoundTripper(t, b, a)
			defer func() { _ = rt.Close() }()
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			client := &http.Client{Transport: rt}
			afterRefusal := 0
			for {
				refusedBeforeRequest := ap.refused.Load()
				req, err := http.NewRequestWithContext(ctx, "GET", "https://n4.invalid/fixture", nil)
				if err != nil {
					t.Fatal(err)
				}
				res, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(res.Body)
				_ = res.Body.Close()
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("body intact=%t err=%v packet_max=%d accepted_max=%d refused=%d", bytes.Equal(got, payload), err, trace.Snapshot().PacketMax, ap.acceptedMax.Load(), ap.refused.Load())
				}
				stats := trace.Snapshot()
				if refusedBeforeRequest > 0 {
					afterRefusal++
				}
				accepted := ap.acceptedMax.Load()
				ready := accepted >= 1430
				if limit < 1452 {
					ready = accepted > 1200 && afterRefusal >= 3
				}
				if ready {
					if stats.PacketMax > 1452 {
						t.Fatalf("packet_max=%d > 1452", stats.PacketMax)
					}
					t.Logf("packet_max=%d accepted_max=%d limit=%d refused=%d subsequent_transfers=%d intact_bytes=%d", stats.PacketMax, accepted, limit, ap.refused.Load(), afterRefusal, len(got))
					break
				}
				if ctx.Err() != nil {
					t.Fatalf("no larger QUIC packet: packet_max=%d, refused=%d", stats.PacketMax, ap.refused.Load())
				}
			}
		})
	}
}

// The test uses the measured transport settings directly, without importing n4.
func testQUICConfig(client bool) *quic.Config {
	c := &quic.Config{CongestionControl: quic.CongestionControlBBRv3, BBRNoLowerBounds: true, BBRLossThresholdPercent: 5, PMTUBlackHoleDetection: true, ScaledStreamGapLimit: true, ACKDecimation: client, InitialPacketSize: 1200, HandshakeIdleTimeout: 20 * time.Second}
	if client {
		c.InitialStreamReceiveWindow = 48 << 20
		c.MaxStreamReceiveWindow = 48 << 20
		c.InitialConnectionReceiveWindow = 64 << 20
		c.MaxConnectionReceiveWindow = 64 << 20
	}
	return c
}
func testRoundTripper(t *testing.T, client, server *Engine) *http3.Transport {
	t.Helper()
	tr := &quic.Transport{Conn: client.PacketConn()}
	t.Cleanup(func() { _ = tr.Close() })
	return &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, QUICConfig: testQUICConfig(true), Dial: func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
		return tr.Dial(ctx, Addr{Key: server.PublicKey()}, tc, qc)
	}}
}

type Trace struct{ packetMax atomic.Uint64 }

func (t *Trace) New(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return t }
func (t *Trace) AddProducer() qlogwriter.Recorder                              { return t }
func (t *Trace) SupportsSchemas(s string) bool                                 { return s == qlog.EventSchema }
func (t *Trace) Close() error                                                  { return nil }
func (t *Trace) RecordEvent(event qlogwriter.Event) {
	if e, ok := event.(qlog.PacketSent); ok {
		n := uint64(e.Raw.Length)
		for old := t.packetMax.Load(); n > old; old = t.packetMax.Load() {
			if t.packetMax.CompareAndSwap(old, n) {
				break
			}
		}
	}
}
func (t *Trace) Snapshot() struct{ PacketMax uint64 } {
	return struct{ PacketMax uint64 }{t.packetMax.Load()}
}
