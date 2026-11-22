package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"tailscale.com/derp"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/net/wsconn"

	"github.com/Silo-Server/shunpike/coordination/protocol"
	"github.com/Silo-Server/shunpike/engine"
)

type regionWebSocketConn struct {
	net.Conn
	socket *websocket.Conn
}

func (c *regionWebSocketConn) Close() error { return c.socket.CloseNow() }

type regionDiscoReceipt struct {
	source  protocol.NodeKey
	payload []byte
}
type regionDiscoObserver struct {
	net.Conn
	pending  []byte
	receipts chan<- regionDiscoReceipt
}

func (c *regionDiscoObserver) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.pending = append(c.pending, p[:n]...)
	for len(c.pending) >= 5 {
		size := int(binary.BigEndian.Uint32(c.pending[1:5]))
		if len(c.pending) < 5+size {
			break
		}
		body := c.pending[5 : 5+size]
		if c.pending[0] == byte(derp.FrameRecvPacket) && len(body) >= 32+78 {
			var src protocol.NodeKey
			copy(src[:], body[:32])
			select {
			case c.receipts <- regionDiscoReceipt{src, bytes.Clone(body[32:])}:
			default:
			}
		}
		c.pending = c.pending[5+size:]
	}
	return n, err
}

func awaitRegionDisco(t *testing.T, ctx context.Context, receipts <-chan regionDiscoReceipt, src protocol.NodeKey, dk protocol.DiscoKey) {
	t.Helper()
	select {
	case receipt := <-receipts:
		if receipt.source != src || len(receipt.payload) < 78 || !bytes.Equal(receipt.payload[:6], []byte{'T', 'S', 0xf0, 0x9f, 0x92, 0xac}) || !bytes.Equal(receipt.payload[6:38], dk[:]) {
			t.Fatalf("unexpected discovery receipt: %+v", receipt)
		}
	case <-ctx.Done():
		t.Fatal("discovery frame missing from signaling stream:", ctx.Err())
	}
}

func TestRegionOverWebSocket(t *testing.T) {
	f := newRegionFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	f.ctx = ctx
	stunAddr, closeSTUN := stuntest.Serve(t)
	t.Cleanup(closeSTUN)
	var mu sync.Mutex
	principal := f.p
	credential := "initial"
	accepted := make(chan Principal, 16)
	finished := make(chan Principal, 16)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		p, want := principal, credential
		mu.Unlock()
		if req.Header.Get("Authorization") != want {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		socket, err := websocket.Accept(w, req, &websocket.AcceptOptions{Subprotocols: []string{"derp"}})
		if err != nil {
			return
		}
		defer func() { _ = socket.CloseNow() }()
		if socket.Subprotocol() != "derp" {
			t.Error("missing derp subprotocol")
			return
		}
		accepted <- p
		nc := &regionWebSocketConn{Conn: wsconn.NetConn(req.Context(), socket, websocket.MessageBinary, req.RemoteAddr), socket: socket}
		_ = f.r.Serve(req.Context(), nc, p)
		finished <- p
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	dial := engine.WebSocketDialer(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, func(context.Context) (http.Header, error) {
		mu.Lock()
		defer mu.Unlock()
		return http.Header{"Authorization": []string{credential}}, nil
	})
	hostReceipts := make(chan regionDiscoReceipt, 64)
	deviceReceipts := make(chan regionDiscoReceipt, 64)
	hostKey := engine.NodePrivateFromBytes(f.host.Raw32())
	// The host entry exists before the engine's first local signaling dial.
	host, err := engine.New(ctx, engine.Config{PrivateKey: hostKey, StaticNetwork: true, STUNServers: []string{stunAddr.String()}, Signaling: &engine.Signaling{Dial: func(c context.Context, _ string) (net.Conn, error) {
		nc, err := f.r.DialLocal(ctx)
		if err != nil {
			return nil, err
		}
		return &regionDiscoObserver{Conn: nc, receipts: hostReceipts}, nil
	}}})
	requireNoError(t, err)
	t.Cleanup(func() { requireNoError(t, host.Close()) })
	device, err := engine.New(ctx, engine.Config{PrivateKey: engine.NodePrivateFromBytes(f.device.Raw32()), StaticNetwork: true, STUNServers: []string{stunAddr.String()}, Regions: []protocol.Region{{ID: 0, Code: "local", URL: srv.URL}}, Signaling: &engine.Signaling{Dial: func(c context.Context, url string) (net.Conn, error) {
		nc, err := dial(c, url)
		if err != nil {
			return nil, err
		}
		return &regionDiscoObserver{Conn: nc, receipts: deviceReceipts}, nil
	}}})
	requireNoError(t, err)
	t.Cleanup(func() { requireNoError(t, device.Close()) })
	reg, err := device.Registration()
	requireNoError(t, err)
	requireNoError(t, f.s.Register(ctx, f.p, reg))
	f.d.Invalidate(f.p.NodeKey)
	f.warm(t, f.p.NodeKey)
	requireNoError(t, f.st.PutHost(ctx, HostEntry{Label: "host", NodeKey: host.PublicKey(), DiscoKey: host.DiscoKey(), PresenceExpires: time.Now().Add(time.Hour)}, time.Now()))
	f.d.Invalidate(host.PublicKey())
	f.warm(t, host.PublicKey())
	for _, pair := range [][2]*engine.Engine{{host, device}, {device, host}} {
		peer := pair[1]
		requireNoError(t, pair[0].SetPeers([]engine.Peer{{NodeKey: peer.PublicKey(), DiscoKey: peer.DiscoKey(), HomeRegion: 0, Expires: time.Now().Add(time.Minute)}}))
	}
	awaitRegionDisco(t, ctx, hostReceipts, device.PublicKey(), device.DiscoKey())
	awaitRegionDisco(t, ctx, deviceReceipts, host.PublicKey(), host.DiscoKey())
	for _, pair := range [][2]*engine.Engine{{host, device}, {device, host}} {
		peer := pair[1]
		requireNoError(t, pair[0].SetPeers([]engine.Peer{{NodeKey: peer.PublicKey(), DiscoKey: peer.DiscoKey(), HomeRegion: 0, Endpoints: []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), peer.LocalPort())}, Expires: time.Now().Add(time.Minute)}}))
	}
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("WebSocket engine did not connect")
	}
	for {
		dr, de := device.Registration()
		hr, he := host.Registration()
		requireNoError(t, de)
		requireNoError(t, he)
		if len(dr.Confirmations) > 0 && len(hr.Confirmations) > 0 {
			break
		}
		select {
		case <-device.Changed():
		case <-host.Changed():
		case <-ctx.Done():
			t.Fatal("engine discovery did not complete")
		}
	}
	mu.Lock()
	principal.Expires = time.Now().Add(3 * time.Second)
	rotated := principal
	credential = "rotated"
	mu.Unlock()
	f.r.Disconnect(f.p.NodeKey)
	for {
		select {
		case p := <-accepted:
			if p.Expires.Equal(rotated.Expires) {
				goto reconnected
			}
		case <-ctx.Done():
			t.Fatal("rotated credential did not reconnect")
		}
	}
reconnected:
	for {
		select {
		case p := <-finished:
			if p.Expires.Equal(rotated.Expires) {
				if time.Now().Before(p.Expires) || time.Now().After(p.Expires.Add(100*time.Millisecond)) {
					t.Fatalf("rotated expiry closed at %v, deadline %v", time.Now(), p.Expires)
				}
				return
			}
		case <-ctx.Done():
			t.Fatal("rotated connection did not expire")
		}
	}
}
