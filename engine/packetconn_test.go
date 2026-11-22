package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/types/key"

	"github.com/Silo-Server/shunpike/coordination/protocol"
)

type fixtureBind struct {
	closed chan struct{}
	once   sync.Once
}

func (b *fixtureBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) { return nil, 0, nil }
func (b *fixtureBind) Close() error                                    { b.once.Do(func() { close(b.closed) }); return nil }
func (b *fixtureBind) SetMark(uint32) error                            { return nil }
func (b *fixtureBind) Send([][]byte, conn.Endpoint, int) error         { return nil }
func (b *fixtureBind) ParseEndpoint(string) (conn.Endpoint, error)     { return fixtureEndpoint{}, nil }
func (b *fixtureBind) BatchSize() int                                  { return 2 }

type fixtureEndpoint struct{}

func (fixtureEndpoint) ClearSrc()           {}
func (fixtureEndpoint) SrcToString() string { return "" }
func (fixtureEndpoint) DstToString() string { return "fixture" }
func (fixtureEndpoint) DstToBytes() []byte  { return nil }
func (fixtureEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (fixtureEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type sentinelBind struct {
	fixtureBind
	mu       sync.Mutex
	isClosed bool
	frames   chan []byte
	taken    chan struct{}
}

func (b *sentinelBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.isClosed = true
	// Like magicsock, send the sentinel while holding the closure mutex.
	b.frames <- nil
	return b.fixtureBind.Close()
}

func (b *sentinelBind) receive(slab []byte, packets []conn.ReceivedPacket) (int, error) {
	for frame := range b.frames {
		b.mu.Lock()
		closed := b.isClosed
		b.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		if frame == nil {
			continue
		}
		packets[0] = conn.ReceivedPacket{Size: copy(slab, frame), Endpoint: fixtureEndpoint{}}
		b.taken <- struct{}{}
		return 1, nil
	}
	return 0, net.ErrClosed
}

func TestPacketConnCloseDrainsBindSentinel(t *testing.T) {
	b := &sentinelBind{
		fixtureBind: fixtureBind{closed: make(chan struct{})},
		frames:      make(chan []byte, 1),
		taken:       make(chan struct{}, 1),
	}
	blocked := func([]byte, []conn.ReceivedPacket) (int, error) {
		<-b.closed
		return 0, net.ErrClosed
	}
	p := newPacketConn(b, []conn.ReceiveFunc{blocked, blocked, b.receive}, func(protocol.NodeKey) bool { return true })
	p.setPeers(map[key.NodePublic]conn.Endpoint{key.NewNode().Public(): fixtureEndpoint{}})
	done := make(chan error, 1)
	var once sync.Once
	startClose := func() { once.Do(func() { go func() { done <- p.Close() }() }) }
	t.Cleanup(func() {
		startClose()
		// Release the blocked sentinel send on the red run and join Close.
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		for {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("cleanup Close: %v", err)
				}
				return
			case <-b.frames:
			case <-timer.C:
				t.Error("cleanup could not release PacketConn.Close")
				return
			}
		}
	})
	// No ReadFrom calls: the QUIC listener has already stopped consuming.
	b.frames <- []byte("A")
	select {
	case <-b.taken:
	case <-time.After(2 * time.Second):
		t.Fatal("receive worker did not take frame A")
	}
	b.frames <- []byte("B")
	if got := len(b.frames); got != 1 {
		t.Fatalf("queued frames=%d, want frame B in the one-slot channel", got)
	}
	startClose()
	select {
	case err := <-done:
		// Leave the completion available for cleanup to join without draining.
		done <- err
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PacketConn.Close blocked: bind sentinel had no consumer")
	}
}

func TestPacketConnReportsReceiveFailure(t *testing.T) {
	b := &fixtureBind{closed: make(chan struct{})}
	want := errors.New("receive failed")
	first := true
	p := newPacketConn(b, []conn.ReceiveFunc{func([]byte, []conn.ReceivedPacket) (int, error) {
		if first {
			first = false
			return 0, want
		}
		<-b.closed
		return 0, net.ErrClosed
	}}, nil)
	defer func() { _ = p.Close() }()
	_ = p.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err := p.ReadFrom(make([]byte, 1200))
	if !errors.Is(err, want) {
		t.Fatalf("ReadFrom error=%v, want %v", err, want)
	}
}
func TestPacketConnKeepsBatchUntilLastCopy(t *testing.T) {
	b := &fixtureBind{closed: make(chan struct{})}
	calls := make(chan *byte, 3)
	ready := make(chan struct{})
	call := 0
	ep := fixtureEndpoint{}
	p := newPacketConn(b, []conn.ReceiveFunc{func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		<-ready
		call++
		if call > 3 {
			<-b.closed
			return 0, net.ErrClosed
		}
		copy(slab, []string{"abcd", "efgh", "ijkl"}[call-1])
		packets[0] = conn.ReceivedPacket{Offset: 0, Size: 2, Endpoint: ep}
		packets[1] = conn.ReceivedPacket{Offset: 2, Size: 2, Endpoint: ep}
		calls <- &slab[0]
		return 2, nil
	}}, nil)
	defer func() { _ = p.Close() }()
	p.setPeers(map[key.NodePublic]conn.Endpoint{key.NewNode().Public(): ep})
	close(ready)
	_ = p.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1200)
	n, _, err := p.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "ab" {
		t.Fatalf("first read=%q err=%v", buf[:n], err)
	}
	firstSlab := <-calls
	var secondSlab *byte
	select {
	case secondSlab = <-calls:
		if secondSlab == firstSlab {
			t.Fatal("slab reused before final packet copied")
		}
	case <-time.After(time.Second):
		t.Fatal("second receive did not overlap the first batch's remaining copy")
	}
	n, _, err = p.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "cd" {
		t.Fatalf("second read=%q err=%v", buf[:n], err)
	}
	// Accepting batch two releases the producer to reuse slab one. Slab two
	// still holds its last packet and must not be overwritten by receive three.
	n, _, err = p.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "ef" {
		t.Fatalf("third read=%q err=%v", buf[:n], err)
	}
	select {
	case thirdSlab := <-calls:
		if thirdSlab != firstSlab || thirdSlab == secondSlab {
			t.Fatal("third receive did not reuse only the fully copied slab")
		}
	case <-time.After(time.Second):
		t.Fatal("batch did not release after last copy")
	}
	for i, want := range []string{"gh", "ij", "kl"} {
		n, _, err = p.ReadFrom(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("remaining read %d=%q err=%v, want %q", i, buf[:n], err, want)
		}
	}
}

type sizedFixtureBind struct {
	fixtureBind
	size int
}

func (b *sizedFixtureBind) BatchSize() int { return b.size }

func TestPacketConnFiltersEmptyEntries(t *testing.T) {
	b := &sizedFixtureBind{fixtureBind{closed: make(chan struct{})}, 5}
	ready := make(chan struct{})
	ep := fixtureEndpoint{}
	peer := key.NewNode().Public()
	first := true
	p := newPacketConn(b, []conn.ReceiveFunc{func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		<-ready
		if !first {
			<-b.closed
			return 0, net.ErrClosed
		}
		first = false
		copy(slab[8:], "left\x07right")
		packets[0] = conn.ReceivedPacket{Offset: 8, Size: 4, Endpoint: ep}
		// magicsock blanks only Size, leaving the previous endpoint and offset.
		packets[1] = conn.ReceivedPacket{Offset: len(slab), Endpoint: ep}
		packets[2] = conn.ReceivedPacket{}
		// The batching layer can append this one-byte GSO sentinel.
		packets[3] = conn.ReceivedPacket{Offset: 12, Size: 1, Endpoint: ep}
		packets[4] = conn.ReceivedPacket{Offset: 13, Size: 5, Endpoint: ep}
		return 5, nil
	}}, nil)
	defer func() { _ = p.Close() }()
	p.setPeers(map[key.NodePublic]conn.Endpoint{peer: ep})
	close(ready)
	_ = p.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 32)
	for i, data := range []string{"left", "\x07", "right"} {
		n, from, err := p.ReadFrom(buf)
		if err != nil || string(buf[:n]) != data || from != (Addr{Key: nodeKey(peer)}) {
			t.Fatalf("read %d=%q from %v error=%v, want %q from %v", i, buf[:n], from, err, data, Addr{Key: nodeKey(peer)})
		}
	}
	if c := p.Counters(); c.UDP4 != 3 || c.LazyDrops != 0 {
		t.Errorf("counters=%+v, want 3 UDP datagrams and no lazy drops for blank slots", c)
	}
}

// fixturePacketConn supplies full batches through the real receive worker.
func fixturePacketConn(tb testing.TB, size int) *packetConn {
	tb.Helper()
	b := &sizedFixtureBind{fixtureBind{closed: make(chan struct{})}, size}
	ready := make(chan struct{})
	ep := fixtureEndpoint{}
	p := newPacketConn(b, []conn.ReceiveFunc{func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		<-ready
		select {
		case <-b.closed:
			return 0, net.ErrClosed
		default:
		}
		for i := range packets {
			packets[i] = conn.ReceivedPacket{Offset: i * 1200, Size: 1200, Endpoint: ep}
			slab[i*1200] = byte(i)
		}
		return len(packets), nil
	}}, nil)
	p.setPeers(map[key.NodePublic]conn.Endpoint{key.NewNode().Public(): ep})
	close(ready)
	tb.Cleanup(func() { _ = p.Close() })
	return p
}

func TestPacketConnCurrentBatchAllocations(t *testing.T) {
	p := fixturePacketConn(t, 2)
	buf := make([]byte, 1200)
	if _, _, err := p.ReadFrom(buf); err != nil {
		t.Fatal(err)
	}
	var from net.Addr
	var err error
	allocs := testing.AllocsPerRun(1000, func() {
		p.next = 0 // Keep the first batch current throughout the measurement.
		_, from, err = p.ReadFrom(buf)
	})
	if err != nil || from == nil {
		t.Fatalf("current batch read: from=%v error=%v", from, err)
	}
	if allocs != 0 {
		t.Fatalf("ReadFrom current batch allocations=%g, want 0", allocs)
	}
}

func TestPacketConnCurrentBatchCloseAndDeadline(t *testing.T) {
	for _, action := range []string{"Close", "SetReadDeadline", "SetDeadline"} {
		t.Run(action, func(t *testing.T) {
			p := fixturePacketConn(t, 2)
			buf := make([]byte, 1200)
			if _, _, err := p.ReadFrom(buf); err != nil {
				t.Fatal(err)
			}
			want := os.ErrDeadlineExceeded
			switch action {
			case "Close":
				_ = p.Close()
				want = net.ErrClosed
			case "SetReadDeadline":
				_ = p.SetReadDeadline(time.Now().Add(-time.Second))
			case "SetDeadline":
				_ = p.SetDeadline(time.Now().Add(-time.Second))
			}
			if _, _, err := p.ReadFrom(buf); !errors.Is(err, want) {
				t.Fatalf("ReadFrom after %s error=%v, want %v", action, err, want)
			}
		})
	}
}

func TestPacketConnReceiveBatchCounters(t *testing.T) {
	b := &fixtureBind{closed: make(chan struct{})}
	ready := make(chan struct{})
	processed := make(chan struct{})
	ep := fixtureEndpoint{}
	call := 0
	p := newPacketConn(b, []conn.ReceiveFunc{func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		<-ready
		call++
		switch call {
		case 1:
			packets[0] = conn.ReceivedPacket{} // Blank-only receives do not count.
			return 1, nil
		case 2, 3:
			copy(slab, "ab")
			packets[0] = conn.ReceivedPacket{Size: 1, Endpoint: ep}
			packets[1] = conn.ReceivedPacket{Offset: 1, Size: 1, Endpoint: ep}
			return call - 1, nil
		case 4:
			packets[0] = conn.ReceivedPacket{Size: 1} // Unattributed packets do not count.
			return 1, nil
		default:
			close(processed)
			<-b.closed
			return 0, net.ErrClosed
		}
	}}, nil)
	defer func() { _ = p.Close() }()
	p.setPeers(map[key.NodePublic]conn.Endpoint{key.NewNode().Public(): ep})
	close(ready)
	_ = p.SetReadDeadline(time.Now().Add(time.Second))
	for range 3 {
		if _, _, err := p.ReadFrom(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
	}
	<-processed // The dropped-only call has passed through receive filtering.
	_ = p.Close()
	data, err := json.Marshal(p.Counters())
	if err != nil {
		t.Fatal(err)
	}
	var counts map[string]any
	if err := json.Unmarshal(data, &counts); err != nil {
		t.Fatal(err)
	}
	if counts["receive_batches"] != float64(2) || counts["mean_datagrams_per_receive_batch"] != 1.5 {
		t.Fatalf("counters=%s, want receive_batches=2 and mean_datagrams_per_receive_batch=1.5", data)
	}
}

func BenchmarkPacketConnReadFrom(b *testing.B) {
	for _, size := range []int{2, 64} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			p := fixturePacketConn(b, size)
			buf := make([]byte, 1200)
			b.ReportAllocs()
			b.SetBytes(int64(len(buf)))
			b.ResetTimer()
			for b.Loop() {
				if _, _, err := p.ReadFrom(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
