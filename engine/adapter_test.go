package engine

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/types/key"

	"github.com/darthShadow/shunpike/coordination/protocol"
)

func TestPacketConnDropsUnknownSource(t *testing.T) {
	b := &fixtureBind{closed: make(chan struct{})}
	processed := make(chan struct{})
	calls := 0
	p := newPacketConn(b, []conn.ReceiveFunc{func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		calls++
		if calls == 1 {
			packets[0] = conn.ReceivedPacket{Size: copy(slab, "unknown"), Endpoint: fixtureEndpoint{}}
			return 1, nil
		}
		close(processed)
		<-b.closed
		return 0, net.ErrClosed
	}}, nil)
	defer func() { _ = p.Close() }()
	select {
	case <-processed:
	case <-time.After(time.Second):
		t.Fatal("unknown source was queued instead of dropped")
	}
	if c := p.Counters(); c.LazyDrops != 1 {
		t.Fatalf("LazyDrops=%d, want 1", c.LazyDrops)
	}
	_ = p.SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, err := p.ReadFrom(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read=%v, want deadline", err)
	}
}

func TestReceiveFunctionOrder(t *testing.T) {
	for kind := range 3 {
		t.Run(string(rune('0'+kind)), func(t *testing.T) {
			b := &fixtureBind{closed: make(chan struct{})}
			ready := make(chan struct{})
			ep := fixtureEndpoint{}
			k := key.NewNode().Public()
			blocked := func([]byte, []conn.ReceivedPacket) (int, error) { <-b.closed; return 0, net.ErrClosed }
			fns := []conn.ReceiveFunc{blocked, blocked, blocked}
			once := false
			fns[kind] = func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
				<-ready
				if once {
					return blocked(slab, packets)
				}
				once = true
				packets[0] = conn.ReceivedPacket{Size: copy(slab, "data"), Endpoint: ep}
				return 1, nil
			}
			p := newPacketConn(b, fns, func(protocol.NodeKey) bool { return true })
			defer func() { _ = p.Close() }()
			p.setPeers(map[key.NodePublic]conn.Endpoint{k: ep})
			close(ready)
			_ = p.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, err := p.ReadFrom(make([]byte, 64)); err != nil {
				t.Fatal(err)
			}
			c := p.Counters()
			counts := []uint64{c.UDP4, c.UDP6, c.DERP}
			for i, n := range counts {
				want := uint64(0)
				if i == kind {
					want = 1
				}
				if n != want {
					t.Fatalf("kind=%d counter=%d got=%d want=%d", kind, i, n, want)
				}
			}
		})
	}
}
