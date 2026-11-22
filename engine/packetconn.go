package engine

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/types/key"

	"github.com/Silo-Server/shunpike/coordination/protocol"
)

// DirectPacketLimit is 1500 minus the IPv6 (40) and UDP (8) headers.
// IPv4 permits 1472, but pinned quic-go caps packets at this common limit.
// Magicsock strips our eight bytes of headroom on direct UDP sends.
const DirectPacketLimit = 1452

// Counters are cumulative from socket creation, including establishment.
// DERP includes both received media packets and successful media sends, even
// when the relay drops those sends before delivery. Disco frames are excluded.
type Counters struct {
	UDP4     uint64 `json:"udp4"`
	UDP6     uint64 `json:"udp6"`
	DERP     uint64 `json:"derp"`
	DERPSent uint64 `json:"derp_sent"`

	LazyDrops uint64 `json:"lazy_drops"`
	DERPDrops uint64 `json:"derp_drops"`

	GSOEnabled           bool    `json:"gso_enabled"`
	BindSends            uint64  `json:"bind_sends"`
	SendDatagrams        uint64  `json:"send_datagrams"`
	MeanDatagramsPerSend float64 `json:"mean_datagrams_per_bind_send"`
	// Receive batches and their mean include only datagrams admitted to ReadFrom.
	ReceiveBatches               uint64  `json:"receive_batches"`
	MeanDatagramsPerReceiveBatch float64 `json:"mean_datagrams_per_receive_batch"`
}
type incomingBatch struct {
	slab      []byte
	packets   []conn.ReceivedPacket
	addresses []net.Addr
	count     int
}

// packetConn borrows receive slabs until ReadFrom copies each datagram. There
// is no unbounded queue and no user-space congestion drop.
type packetConn struct {
	bind               conn.Bind
	relayedDataAllowed func(protocol.NodeKey) bool
	mu                 sync.Mutex
	peers              map[key.NodePublic]conn.Endpoint
	reverse            map[conn.Endpoint]net.Addr
	counts             Counters
	receiveDatagrams   uint64
	gso                bool

	queue         chan *incomingBatch
	readErrors    chan error
	readMu        sync.Mutex
	current       *incomingBatch
	next          int
	closed        chan struct{}
	isClosed      atomic.Bool
	once          sync.Once
	workers       sync.WaitGroup
	readDeadline  atomic.Pointer[time.Time]
	writeDeadline time.Time
	wake          chan struct{}
	pool          sync.Pool
}

// newPacketConn consumes UDP4, UDP6 and DERP. Close owns the bind.
func newPacketConn(b conn.Bind, fns []conn.ReceiveFunc, allow func(protocol.NodeKey) bool) *packetConn {
	p := &packetConn{bind: b, relayedDataAllowed: allow, peers: map[key.NodePublic]conn.Endpoint{}, reverse: map[conn.Endpoint]net.Addr{}, queue: make(chan *incomingBatch), readErrors: make(chan error, 1), closed: make(chan struct{}), wake: make(chan struct{})}
	p.pool.New = func() any { b := make([]byte, 65535+8); return &b }
	for kind, fn := range fns {
		p.workers.Add(1)
		go p.receive(kind, fn)
	}
	return p
}
func (p *packetConn) receive(kind int, fn conn.ReceiveFunc) {
	defer p.workers.Done()
	// The reader accepts a new batch only after copying its current batch.
	// Once a send on the unbuffered queue completes, this worker's previous
	// slab is free. Two slabs therefore overlap receive and copy without a
	// separate release handshake, including when other workers interleave.
	var ring [2]incomingBatch
	for i := range ring {
		ring[i] = incomingBatch{slab: make([]byte, 2*(1<<16-1)), packets: make([]conn.ReceivedPacket, p.bind.BatchSize()), addresses: make([]net.Addr, p.bind.BatchSize())}
	}
	next := 0
	for {
		batch := &ring[next]
		n, err := fn(batch.slab, batch.packets)
		if err != nil {
			select {
			case <-p.closed:
				return
			default:
			}
			select {
			case p.readErrors <- err:
			default:
			}
			return
		}
		batch.count = 0
		p.mu.Lock()
		for _, packet := range batch.packets[:n] {
			// magicsock blanks Size on consumed control packets, but can
			// leave the previous endpoint and offset in the slot.
			if packet.Size == 0 {
				continue
			}
			switch kind {
			case 0:
				p.counts.UDP4++
			case 1:
				p.counts.UDP6++
			case 2:
				p.counts.DERP++
			}
			addr, known := p.reverse[packet.Endpoint]
			drop := false
			if !known {
				p.counts.LazyDrops++
				drop = true
			}
			if kind == 2 && (p.relayedDataAllowed == nil || !p.relayedDataAllowed(addrKey(addr))) {
				p.counts.DERPDrops++
				drop = true
			}
			if kind >= 3 {
				drop = true
			}
			if !drop {
				batch.packets[batch.count] = packet
				batch.addresses[batch.count] = addr
				batch.count++
			}
		}
		if batch.count > 0 {
			p.counts.ReceiveBatches++
			p.receiveDatagrams += uint64(batch.count)
		}
		p.mu.Unlock()
		if batch.count == 0 {
			continue
		}
		select {
		case p.queue <- batch:
			next ^= 1
		case <-p.closed:
			// Drop the batch and keep receiving until the bind reports closure.
			// magicsock's Bind.Close sends a sentinel into a one-slot DERP
			// channel while holding its mutex, so it still needs a consumer.
		}
	}
}

// setPeers replaces both pointer-to-address attribution and outbound handles.
func (p *packetConn) setPeers(peers map[key.NodePublic]conn.Endpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.peers = make(map[key.NodePublic]conn.Endpoint, len(peers))
	p.reverse = make(map[conn.Endpoint]net.Addr, len(peers))
	// Cache boxed addresses so ReadFrom reuses the same net.Addr value.
	for k, ep := range peers {
		p.peers[k] = ep
		p.reverse[ep] = Addr{Key: nodeKey(k)}
	}
}

// Counters returns a consistent snapshot without resetting any counter.
func (p *packetConn) Counters() Counters {
	p.mu.Lock()
	defer p.mu.Unlock()
	counts := p.counts
	counts.GSOEnabled = p.gso
	if counts.BindSends > 0 {
		counts.MeanDatagramsPerSend = float64(counts.SendDatagrams) / float64(counts.BindSends)
	}
	if counts.ReceiveBatches > 0 {
		counts.MeanDatagramsPerReceiveBatch = float64(p.receiveDatagrams) / float64(counts.ReceiveBatches)
	}
	if sender, ok := p.bind.(interface{ DERPDataSent() int64 }); ok {
		counts.DERPSent = uint64(sender.DERPDataSent())
		counts.DERP += counts.DERPSent
	}
	return counts
}

// ReadFrom copies one admitted datagram, respecting closure and deadlines.
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	for {
		if p.isClosed.Load() {
			return 0, nil, net.ErrClosed
		}
		deadline := p.readDeadline.Load()
		if deadline != nil && !deadline.IsZero() && !time.Now().Before(*deadline) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		if batch := p.current; batch != nil {
			packet := batch.packets[p.next]
			addr := batch.addresses[p.next]
			n := copy(b, packet.Bytes(batch.slab))
			p.next++
			if p.next == batch.count {
				p.current = nil
				p.next = 0
			}
			return n, addr, nil
		}
		// Snapshot the wake channel and deadline together to avoid missing a
		// deadline change between the fast check and the blocking select.
		p.mu.Lock()
		deadline, wake := p.readDeadline.Load(), p.wake
		p.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if deadline != nil && !deadline.IsZero() {
			timer = time.NewTimer(time.Until(*deadline))
			timeout = timer.C
		}
		select {
		case <-p.closed:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case err := <-p.readErrors:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, err
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-wake:
			if timer != nil {
				timer.Stop()
			}
		case batch := <-p.queue:
			if timer != nil {
				timer.Stop()
			}
			p.current = batch
			p.next = 0
		}
	}
}
func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return p.writeTo(b, addr)
}
func (p *packetConn) writeTo(b []byte, addr net.Addr) (int, error) {
	a, ok := addr.(Addr)
	if !ok {
		return 0, conn.ErrWrongEndpointType
	}
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	p.mu.Lock()
	ep, known := p.peers[nodePublic(a.Key)]
	deadline := p.writeDeadline
	p.mu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if !known {
		return 0, fmt.Errorf("peer has no active lease")
	}
	if len(b) > DirectPacketLimit {
		return 0, syscall.EMSGSIZE
	}
	buf := p.pool.Get().(*[]byte)
	defer p.pool.Put(buf)
	copy((*buf)[8:], b)
	p.mu.Lock()
	p.counts.BindSends++
	p.counts.SendDatagrams++
	p.mu.Unlock()
	err := p.bind.Send([][]byte{(*buf)[:len(b)+8]}, ep, 8)
	// These are the pinned implementation's unexported loss-like refusals.
	if err != nil && (err.Error() == "magicsock: network down" || err.Error() == "no UDP or DERP addr" || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)) {
		err = nil
	}
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// SetGSO enables the optional quic-go segmented-write hook before QUIC starts.
func (p *packetConn) SetGSO(enabled bool) { p.mu.Lock(); p.gso = enabled; p.mu.Unlock() }

// SupportsGSO reports whether quic-go may submit a paced train of datagrams.
func (p *packetConn) SupportsGSO() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.gso }

// WriteSegments splits a train into independent buffers with Geneve headroom.
// A zero segment size sends one datagram. Send borrows buffers only until return.
// Address, deadline, and loss-like errors follow WriteTo's contract.
func (p *packetConn) WriteSegments(b []byte, addr net.Addr, size uint16) (int, error) {
	if size == 0 {
		return p.WriteTo(b, addr)
	}
	return p.writeSegments(b, addr, int(size))
}

func (p *packetConn) writeSegments(b []byte, addr net.Addr, size int) (int, error) {
	a, ok := addr.(Addr)
	if !ok {
		return 0, conn.ErrWrongEndpointType
	}
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	p.mu.Lock()
	ep, known := p.peers[nodePublic(a.Key)]
	deadline := p.writeDeadline
	p.mu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if !known {
		return 0, fmt.Errorf("peer has no active lease")
	}
	if size > DirectPacketLimit {
		return 0, syscall.EMSGSIZE
	}
	var buffers [][]byte
	var borrowed []*[]byte
	defer func() {
		for _, buf := range borrowed {
			p.pool.Put(buf)
		}
	}()
	for offset := 0; offset < len(b) || offset == 0; offset += size {
		n := min(size, len(b)-offset)
		buf := p.pool.Get().(*[]byte)
		borrowed = append(borrowed, buf)
		copy((*buf)[8:], b[offset:offset+n])
		buffers = append(buffers, (*buf)[:n+8])
		if len(b) == 0 {
			break
		}
	}
	p.mu.Lock()
	p.counts.BindSends++
	p.counts.SendDatagrams += uint64(len(buffers))
	p.mu.Unlock()
	err := p.bind.Send(buffers, ep, 8)
	// These are the pinned implementation's unexported loss-like refusals.
	if err != nil && (err.Error() == "magicsock: network down" || err.Error() == "no UDP or DERP addr" || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)) {
		err = nil
	}
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
func (p *packetConn) Close() error {
	var err error
	p.once.Do(func() { p.isClosed.Store(true); close(p.closed); err = p.bind.Close(); p.workers.Wait() })
	return err
}
func (p *packetConn) LocalAddr() net.Addr { return Addr{} }
func (p *packetConn) SetDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readDeadline.Store(&t)
	p.writeDeadline = t
	close(p.wake)
	p.wake = make(chan struct{})
	return nil
}
func (p *packetConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readDeadline.Store(&t)
	close(p.wake)
	p.wake = make(chan struct{})
	return nil
}
func (p *packetConn) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writeDeadline = t
	return nil
}

var _ net.PacketConn = (*packetConn)(nil)

// SupportsDF tells the pinned quic-go overlay whether magicsock installs DF
// before exposing every socket. Unrecognized binds keep PMTU discovery off.
func (p *packetConn) SupportsDF() bool {
	b, ok := p.bind.(interface{ SupportsDF() bool })
	return ok && b.SupportsDF()
}

func addrKey(addr net.Addr) protocol.NodeKey {
	if a, ok := addr.(Addr); ok {
		return a.Key
	}
	return protocol.NodeKey{}
}
