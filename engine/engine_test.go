package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/curve25519"
	"tailscale.com/disco"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/magicsock"

	"github.com/Silo-Server/shunpike/coordination/protocol"
)

func TestConfigValidate(t *testing.T) {
	valid := Config{PrivateKey: NodePrivateFromBytes([32]byte{})}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"zero-private", func(c *Config) { c.PrivateKey = NodePrivate{} }},
		{"missing-dial", func(c *Config) { c.Signaling = &Signaling{} }},
		{"malformed-stun", func(c *Config) { c.STUNServers = []string{"invalid"} }},
		{"insecure-region", func(c *Config) { c.Regions = []protocol.Region{{URL: "http://region.invalid/signal"}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			tc.change(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestNodePrivateFromBytesClamps(t *testing.T) {
	for _, raw := range [][32]byte{{0: 255, 31: 255}, {}} {
		k := NodePrivateFromBytes(raw)
		want := raw
		want[0] &= 248
		want[31] &= 127
		want[31] |= 64
		if key.NodePrivateAs[[32]byte](k.scalar) != want {
			t.Fatalf("stored scalar=%x, want %x", key.NodePrivateAs[[32]byte](k.scalar), want)
		}
		pub, err := curve25519.X25519(want[:], curve25519.Basepoint)
		if err != nil {
			t.Fatal(err)
		}
		got := k.Public()
		if !slices.Equal(got[:], pub) {
			t.Fatalf("public=%x, want %x", got, pub)
		}
		if got != NodePrivateFromBytes(raw).Public() || got.IsZero() {
			t.Fatal("public identity unstable or zero")
		}
	}
}

func TestWebSocketDialerNoCredential(t *testing.T) {
	dial := WebSocketDialer(nil, func(context.Context) (http.Header, error) { return nil, ErrNoCredential })
	if _, err := dial(t.Context(), "https://region.invalid/signal"); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("dial error=%v, want ErrNoCredential", err)
	}
}

func TestConfirmationRefreshSendsNoChange(t *testing.T) {
	e, keys := confirmationEngine(1)
	k := keys[0]
	changes := 0
	for i := range 20 {
		e.recordPong(k, e.peer(k).DiscoKey(), &ipnstate.PingResult{Endpoint: "192.0.2.1:41641", LatencySeconds: float64(i)})
		select {
		case <-e.Changed():
			changes++
		default:
		}
	}
	if changes != 1 {
		t.Fatalf("identity changes=%d, want 1", changes)
	}
}

func TestConfirmationEndpointChangeSignals(t *testing.T) {
	e, keys := confirmationEngine(1)
	k := keys[0]
	for _, endpoint := range []string{"192.0.2.1:41641", "192.0.2.2:41641"} {
		e.recordPong(k, e.peer(k).DiscoKey(), &ipnstate.PingResult{Endpoint: endpoint})
		select {
		case <-e.Changed():
		default:
			t.Fatal("new endpoint did not signal")
		}
		reg, err := e.Registration()
		if err != nil {
			t.Fatal(err)
		}
		if len(reg.Confirmations) != 1 || reg.Confirmations[0].Endpoint.String() != endpoint {
			t.Fatalf("confirmations=%v, want %s", reg.Confirmations, endpoint)
		}
	}
}

func TestEngineChangedCoalesces(t *testing.T) {
	e, keys := confirmationEngine(1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, ep := range []string{"192.0.2.1:41641", "192.0.2.2:41641"} {
			e.recordPong(keys[0], e.peer(keys[0]).DiscoKey(), &ipnstate.PingResult{Endpoint: ep})
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("identity sender blocked")
	}
	if cap(e.Changed()) != 1 {
		t.Fatalf("Changed capacity=%d, want 1", cap(e.Changed()))
	}
	select {
	case <-e.Changed():
	default:
		t.Fatal("missing identity change")
	}
	select {
	case <-e.Changed():
		t.Fatal("changes did not coalesce")
	default:
	}
}

func TestPeerIdentityStableAcrossSetPeers(t *testing.T) {
	e, keys := confirmationEngine(2)
	k := keys[0]
	other := e.peerConfig[keys[1]]
	p := e.peerConfig[k]
	var first tailcfg.NodeView
	for i := range 3 {
		p.Endpoints = []netip.AddrPort{netip.MustParseAddrPort(fmt.Sprintf("192.0.2.%d:41641", i+1))}
		ps := []Peer{p, other}
		if i == 1 {
			slices.Reverse(ps)
		}
		if err := e.SetPeers(ps); err != nil {
			t.Fatal(err)
		}
		n := e.peer(k)
		if i == 0 {
			first = n
		} else if n.ID() != first.ID() || !slices.Equal(n.Addresses().AsSlice(), first.Addresses().AsSlice()) {
			t.Fatal("same key changed its synthetic identity")
		}
		if e.discovery[k].first.IsZero() {
			t.Fatal("discovery start lost")
		}
	}
	if e.peer(keys[1]).ID() == first.ID() {
		t.Fatal("different key reused synthetic ID")
	}
}

func TestPeerExpiresAtDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, keys := confirmationEngine(2)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		e.ctx = ctx
		p := e.peerConfig[keys[0]]
		p.Expires = time.Now().Add(200 * time.Millisecond)
		other := e.peerConfig[keys[1]]
		if err := e.SetPeers([]Peer{p, other}); err != nil {
			t.Fatal(err)
		}
		var wakes atomic.Int64
		e.timerWake = func() { wakes.Add(1) }
		done := make(chan struct{})
		go func() { defer close(done); e.expiryLoop() }()
		time.Sleep(199 * time.Millisecond)
		synctest.Wait()
		if !e.IsPeer(p.NodeKey) || wakes.Load() != 0 {
			t.Fatalf("early expiry or timer polling: wakes=%d", wakes.Load())
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if e.IsPeer(p.NodeKey) || !e.IsPeer(other.NodeKey) || wakes.Load() != 1 {
			t.Fatalf("expiry did not isolate deadline peer, wakes=%d", wakes.Load())
		}
		if _, ok := e.peers[keys[0]]; ok {
			t.Fatal("expired peer remains in graph")
		}
		cancel()
		<-done
	})
}

func TestTimeToDirectStampedAtPong(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, keys := confirmationEngine(1)
		k := keys[0]
		e.disco.(*confirmationDisco).status = func(sb *ipnstate.StatusBuilder) { sb.AddPeer(k, &ipnstate.PeerStatus{CurAddr: "192.0.2.1:41641"}) }
		time.Sleep(123 * time.Millisecond)
		e.recordPong(k, e.peer(k).DiscoKey(), &ipnstate.PingResult{Endpoint: "192.0.2.1:41641"})
		if got := e.discovery[k].direct.Sub(e.discovery[k].first); got != 123*time.Millisecond {
			t.Fatalf("pong stamp=%s, want 123ms before any Path call", got)
		}
		time.Sleep(300 * time.Millisecond)
		if got := e.Path(nodeKey(k)).TimeToDirect; got != 123*time.Millisecond {
			t.Fatalf("TimeToDirect=%s, want 123ms", got)
		}
	})
}

func TestObservedPath(t *testing.T) {
	for _, tc := range []struct {
		cur, relay, peerRelay string
		pong                  bool
		want                  PathClass
	}{
		{"", "", "", false, "none"},
		{"", "configured", "", false, "none"},
		{"192.0.2.20:41641", "configured", "", true, "direct"},
		{"192.0.2.20:41641", "", "relay", false, "none"},
		{"invalid", "", "", false, "none"},
	} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			e, keys := confirmationEngine(1)
			k := keys[0]
			e.disco.(*confirmationDisco).status = func(sb *ipnstate.StatusBuilder) {
				sb.AddPeer(k, &ipnstate.PeerStatus{CurAddr: tc.cur, Relay: tc.relay, PeerRelay: tc.peerRelay})
			}
			if tc.pong {
				e.recordPong(k, e.peer(k).DiscoKey(), &ipnstate.PingResult{Endpoint: tc.cur})
			}
			if got := e.Path(nodeKey(k)).Class; got != tc.want {
				t.Fatalf("path=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestPathWithoutPongIsNotDirect(t *testing.T) {
	e, keys := confirmationEngine(1)
	k := keys[0]
	e.disco.(*confirmationDisco).status = func(sb *ipnstate.StatusBuilder) { sb.AddPeer(k, &ipnstate.PeerStatus{CurAddr: "192.0.2.20:41641"}) }
	if got := e.Path(nodeKey(k)).Class; got != "none" {
		t.Fatalf("path without pong=%q, want none", got)
	}
}

func TestCallMeMaybeFitsEnvelope(t *testing.T) {
	e, _ := confirmationEngine(0)
	opts := magicsock.Options{Logf: logger.Discard}
	e.configurePolicy(&opts)
	var eps []tailcfg.Endpoint
	for i := range 100 {
		eps = append(eps, tailcfg.Endpoint{Addr: netip.MustParseAddrPort(fmt.Sprintf("[2001:db8::%x]:41641", i+1))})
	}
	selected := eps
	if opts.MaxCallMeMaybeEndpoints > 0 {
		selected = magicsock.CapEndpoints(eps, opts.MaxCallMeMaybeEndpoints)
	}
	msg := new(disco.CallMeMaybe)
	for _, ep := range selected {
		msg.MyNumber = append(msg.MyNumber, ep.Addr)
	}
	priv := key.NewDisco()
	shared := priv.Shared(key.NewDisco().Public())
	sealed := append([]byte(disco.Magic), priv.Public().AppendTo(nil)...)
	sealed = append(sealed, shared.Seal(msg.AppendMarshal(nil))...)
	if opts.MaxCallMeMaybeEndpoints != 64 || len(selected) != 64 || len(sealed) > 1280 {
		t.Fatalf("CallMeMaybe endpoints=%d sealed bytes=%d, want 64 and <=1280", len(selected), len(sealed))
	}
}

func TestRegistrationCapsEndpoints(t *testing.T) {
	e, _ := confirmationEngine(0)
	for i := range 100 {
		typ := tailcfg.EndpointLocal
		addr := fmt.Sprintf("[2001:db8::%x]:41641", i+1)
		if i >= 80 {
			typ = tailcfg.EndpointSTUN
		} else if i >= 50 {
			addr = fmt.Sprintf("192.0.2.%d:41641", i+1)
		}
		e.endpoints = append(e.endpoints, tailcfg.Endpoint{Addr: netip.MustParseAddrPort(addr), Type: typ})
	}
	r, err := e.Registration()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Endpoints) != 64 {
		t.Fatalf("endpoints=%d, want 64", len(r.Endpoints))
	}
	for i, ep := range r.Endpoints {
		var want netip.AddrPort
		switch {
		case i < 20:
			want = e.endpoints[i+80].Addr
		case i < 50:
			want = e.endpoints[i+30].Addr
		default:
			want = e.endpoints[i-50].Addr
		}
		if ep != want {
			t.Fatalf("endpoint %d=%s, want %s", i, ep, want)
		}
	}
}

func TestNilRelayedDataPolicyDenies(t *testing.T) {
	e, _ := confirmationEngine(0)
	opts := magicsock.Options{Logf: logger.Discard}
	e.configurePolicy(&opts)
	if opts.RelayedDataAllowed == nil || opts.RelayedDataAllowed(key.NewNode().Public()) {
		t.Fatal("nil policy permits relayed data")
	}
}

func TestRecoveryProbesTrackedConnections(t *testing.T) {
	e, _ := confirmationEngine(0)
	opts := magicsock.Options{Logf: logger.Discard}
	e.configurePolicy(&opts)
	if !opts.DirectPathRecovery || opts.DirectPathValidatedFunc == nil {
		t.Fatal("direct path recovery not installed")
	}
	peer := key.NewNode().Public()
	e.connections = map[*quic.Conn]key.NodePublic{new(quic.Conn): peer, new(quic.Conn): peer, new(quic.Conn): key.NewNode().Public()}
	var lines []string
	opts.Logf = func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	opts.DirectPathValidatedFunc(peer)
	want := "engine: path validated peer=" + peer.ShortString() + " probe_now=2"
	if len(lines) != 1 || lines[0] != want {
		t.Fatalf("callback logs=%q, want %q", lines, want)
	}
}

var _ net.PacketConn = (*packetConn)(nil)
