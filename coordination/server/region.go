package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"sync"
	"time"

	"go4.org/mem"
	"tailscale.com/derp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/memnet"
	"tailscale.com/types/key"

	"github.com/Silo-Server/shunpike/coordination/protocol"
)

const admissionWait = 2 * time.Second

// RegionOptions supplies the shared coordinator and peer directory. A zero
// PrivateKey generates a new identity. Budget.Limits sets the envelope numbers
// for every stream and pair; a zero Limits, or a zero field in it, uses the
// protocol default, and Budget's other fields are ignored. The stream DialLocal
// returns carries every pair of its host, so its connection byte total grows with
// the number of devices. LocalConnectionBytes replaces Budget.Limits.ConnectionBytes
// for that stream, and LocalConnectionBytesPerPair raises its limit to that many
// bytes for each pair that carried a frame in the current 90 s window when the
// product is larger. A pair that expires in the window still counts until the
// window ends, so the limit never falls within a window. Zero keeps the shared
// limit. Clock nil uses time.Now and Logger nil discards logs. Keys stay
// in process.
type RegionOptions struct {
	Server                      *Server
	Directory                   *Directory
	PrivateKey                  [32]byte
	Budget                      protocol.Budget
	LocalConnectionBytes        int
	LocalConnectionBytesPerPair int
	Logger                      *slog.Logger
	Clock                       func() time.Time
}

// Forwarder sends a packet to another region endpoint. Payload is lent only
// for the call. Implementations must be comparable for registration/removal.
type Forwarder interface {
	ForwardPacket(src, dst protocol.NodeKey, payload []byte) error
}

// RegionStats is an independent snapshot. Connections counts admitted clients,
// excluding the private delivery client. Refusal reasons have bounded names.
type RegionStats struct {
	Connections int
	Drops       map[string]uint64
	Closes      map[string]uint64
	Replaced    uint64
}

type regionPair struct{ a, b protocol.NodeKey }
type regionPairBudget struct {
	budget  protocol.Budget
	expires time.Time
}

// Region serves discovery-only DERP streams with enrollment, host admission,
// identity binding and a shared envelope on local and forwarded traffic.
type Region struct {
	o              RegionOptions
	openClientInfo func(key.NodePublic, []byte) ([]byte, bool)
	server         *derpserver.Server
	delivery       *derp.Client
	deliveryConn   net.Conn
	deliveryDone   chan struct{}
	mu             sync.Mutex
	closed         bool
	all            map[*regionConn]struct{}
	connections    map[protocol.NodeKey]*regionConn
	pairs          map[regionPair]*regionPairBudget
	stats          RegionStats
	closeOnce      sync.Once
	closeErr       error
}

// NewRegion validates dependencies and constructs one private, authenticated
// in-memory delivery client. Entropy, mesh setup and handshake errors fail the
// construction. No socket or external credential is used by this constructor.
func NewRegion(o RegionOptions) (*Region, error) {
	if o.Server == nil || o.Directory == nil {
		return nil, fmt.Errorf("%w: region requires server and directory", protocol.ErrInvalid)
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	private := key.NewNode()
	if o.PrivateKey != [32]byte{} {
		var err error
		private, err = key.ParseNodePrivateUntyped(mem.S(hex.EncodeToString(o.PrivateKey[:])))
		if err != nil {
			return nil, fmt.Errorf("region private key: %w", err)
		}
	}
	r := &Region{o: o, openClientInfo: private.OpenFrom, all: make(map[*regionConn]struct{}), connections: make(map[protocol.NodeKey]*regionConn), pairs: make(map[regionPair]*regionPairBudget), stats: RegionStats{Drops: make(map[string]uint64), Closes: make(map[string]uint64)}, deliveryDone: make(chan struct{})}
	r.server = derpserver.New(private, func(format string, args ...any) { o.Logger.Debug(fmt.Sprintf(format, args...)) })
	var mesh [32]byte
	if _, err := rand.Read(mesh[:]); err != nil {
		_ = r.server.Close()
		return nil, fmt.Errorf("region mesh entropy: %w", err)
	}
	if err := r.server.SetMeshKey(hex.EncodeToString(mesh[:])); err != nil {
		_ = r.server.Close()
		return nil, fmt.Errorf("region mesh key: %w", err)
	}
	a, b := net.Pipe()
	r.deliveryConn = a
	go func() {
		defer close(r.deliveryDone)
		r.server.Accept(context.Background(), b, bufio.NewReadWriter(bufio.NewReader(b), nil), "delivery")
	}()
	c, err := derp.NewClient(key.NewNode(), a, bufio.NewReadWriter(bufio.NewReader(a), bufio.NewWriter(a)), func(string, ...any) {}, derp.MeshKey(key.DERPMeshFromRaw32(mem.B(mesh[:]))))
	if err == nil {
		_, err = c.Recv() // ServerInfo confirms the delivery client is registered.
	}
	if err != nil {
		_ = a.Close()
		_ = r.server.Close()
		<-r.deliveryDone
		return nil, fmt.Errorf("region delivery handshake: %w", err)
	}
	r.delivery = c
	go func() {
		for {
			if _, err := c.Recv(); err != nil {
				return
			}
		}
	}()
	return r, nil
}

func regionTransportKey(k protocol.NodeKey) key.NodePublic {
	return key.NodePublicFromRaw32(mem.B(k[:]))
}

func regionProtocolKey(k key.NodePublic) protocol.NodeKey {
	var b protocol.NodeKey
	k.AppendTo(b[:0])
	return b
}

type regionConn struct {
	net.Conn
	r       *Region
	ctx     context.Context
	cancel  context.CancelFunc
	p       Principal
	local   bool
	source  protocol.NodeKey
	pending []byte
	// windowAt and carried follow the connection byte window of this stream: carried
	// holds the peers whose pairs carried a frame since windowAt. Both are used
	// under Region.mu and only when LocalConnectionBytesPerPair is set.
	windowAt int64
	carried  map[protocol.NodeKey]struct{}
	budget   protocol.Budget
	limits   protocol.BudgetLimits
	failure  error
}

// Serve authenticates a device and blocks until transport closure, cancellation
// or credential expiry. ClientInfo must prove p.NodeKey. It owns and closes conn;
// authorization and envelope failures are returned to the caller. The directory
// read for admission waits at most 2 seconds, independently of cache lifetimes.
func (r *Region) Serve(ctx context.Context, conn net.Conn, p Principal) error {
	return r.serve(ctx, conn, p, false)
}

func (r *Region) serve(ctx context.Context, conn net.Conn, p Principal, local bool) error {
	defer func() { _ = conn.Close() }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !local {
		if _, err := r.o.Server.Authorize(ctx, p); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	limits := r.o.Budget.Limits
	if local && r.o.LocalConnectionBytes > 0 {
		limits.ConnectionBytes = r.o.LocalConnectionBytes
	}
	c := &regionConn{Conn: conn, r: r, ctx: ctx, cancel: cancel, p: p, local: local, budget: r.o.Budget, limits: limits}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	r.all[c] = struct{}{}
	r.mu.Unlock()
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if !local {
		timer := time.AfterFunc(max(0, p.Expires.Sub(r.o.Clock())), func() { _ = c.Close() })
		defer timer.Stop()
	}
	r.server.Accept(ctx, c, bufio.NewReadWriter(bufio.NewReader(c), nil), conn.RemoteAddr().String())
	return c.failure
}

// DialLocal returns a buffered in-memory connection for this host's engine.
// The caller closes its end.
// Its first ClientInfo must identify a live host in Directory; devices cannot
// enter through this path. Its admission read waits at most 2 seconds; timeout
// closes the returned connection during the handshake. A closed region or canceled
// context refuses the dial.
func (r *Region) DialLocal(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, net.ErrClosed
	}
	a, b := memnet.NewConn("region-local", 256<<10)
	go func() { _ = r.serve(ctx, b, Principal{}, true) }()
	return a, nil
}

func (c *regionConn) Close() error {
	// Transport close may call back into either coordinator; hold no lock here.
	c.cancel()
	err := c.Conn.Close()
	c.r.mu.Lock()
	delete(c.r.all, c)
	if c.r.connections[c.source] == c {
		delete(c.r.connections, c.source)
	}
	c.r.mu.Unlock()
	return err
}

func (c *regionConn) refuse(reason string, err error) error {
	c.r.mu.Lock()
	c.r.stats.Closes[reason]++
	c.r.mu.Unlock()
	c.failure = err
	return err
}

func (c *regionConn) admit(source protocol.NodeKey) error {
	ctx, cancel := context.WithTimeout(c.ctx, admissionWait)
	defer cancel()
	peer, err := c.r.o.Directory.lookupAdmission(ctx, source)
	if err != nil {
		return c.refuse("client_info", fmt.Errorf("region admission: %w", err))
	}
	if peer.IsHost != c.local {
		return c.refuse("client_info", ErrUnauthorized)
	}
	if !c.local {
		if _, err := c.r.o.Server.Authorize(ctx, c.p); err != nil {
			return c.refuse("client_info", err)
		}
	}
	r := c.r
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	old := r.connections[source]
	c.source = source
	r.connections[source] = c
	if old != nil {
		r.stats.Replaced++
	}
	r.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (r *Region) pair(ctx context.Context, src, dst protocol.NodeKey) (PeerEntry, PeerEntry, bool) {
	a, aok := r.o.Directory.Lookup(ctx, src)
	b, bok := r.o.Directory.Lookup(ctx, dst)
	return a, b, aok && bok && src != dst && a.IsHost != b.IsHost
}

// pairBudget is called under mu after authorization; it never allocates state
// for an unknown pair. Both directions and replacement connections share it.
func (r *Region) pairBudget(a, b PeerEntry, now time.Time) *protocol.Budget {
	id := regionPair{a.NodeKey, b.NodeKey}
	if bytes.Compare(id.a[:], id.b[:]) > 0 {
		id.a, id.b = id.b, id.a
	}
	expires := minTime(a.Expires, b.Expires)
	p := r.pairs[id]
	if p == nil || !now.Before(p.expires) {
		for k, held := range r.pairs {
			if !now.Before(held.expires) {
				delete(r.pairs, k)
			}
		}
		p = &regionPairBudget{budget: r.o.Budget}
		r.pairs[id] = p
	}
	p.expires = expires
	return &p.budget
}

// carry records that the pair with peer carried a frame in the current window of
// this stream, and starts a new window when the last one has passed. It is called
// under Region.mu for every frame of the local stream, so it keeps pace with the
// window protocol.CheckFrame keeps for the same frames.
func (c *regionConn) carry(peer protocol.NodeKey, counted bool, nowMillis int64) {
	if c.carried == nil || nowMillis-c.windowAt >= protocol.ConnectionWindowMillis {
		c.carried = make(map[protocol.NodeKey]struct{})
		c.windowAt = nowMillis
	}
	if counted {
		c.carried[peer] = struct{}{}
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (c *regionConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(c.pending) == 0 {
		var header [5]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		ft, size := header[0], binary.BigEndian.Uint32(header[1:])
		if size > 256<<10 || ft == byte(derp.FrameSendPacket) && (size < 32 || size > 32+1280) {
			return 0, c.refuse("size", fmt.Errorf("%w: region frame size", protocol.ErrTooLarge))
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(c.Conn, body); err != nil {
			return 0, err
		}
		first := c.source.IsZero()
		info := ""
		var source protocol.NodeKey
		if first && ft == byte(derp.FrameClientInfo) && len(body) >= 72 {
			copy(source[:], body[:32])
			if source.IsZero() || !c.local && source != c.p.NodeKey {
				return 0, c.refuse("client_info", ErrUnauthorized)
			}
			plain, ok := c.r.openClientInfo(regionTransportKey(source), body[32:])
			if !ok {
				return 0, c.refuse("client_info", ErrUnauthorized)
			}
			info = string(plain)
		}
		var a, b PeerEntry
		live := true
		if ft == byte(derp.FrameSendPacket) && !first {
			var dst protocol.NodeKey
			copy(dst[:], body[:32])
			a, b, live = c.r.pair(c.ctx, c.source, dst)
		}
		r := c.r
		r.mu.Lock()
		now := r.o.Clock()
		budget := protocol.Budget{Limits: c.limits, Pair: &c.budget, Connection: &c.budget}
		if c.local && r.o.LocalConnectionBytesPerPair > 0 {
			c.carry(b.NodeKey, live && ft == byte(derp.FrameSendPacket) && !first, now.UnixMilli())
			budget.ConnectionLimit = func() int { return r.o.LocalConnectionBytesPerPair * len(c.carried) }
		}
		if live && ft == byte(derp.FrameSendPacket) && !first {
			budget.Pair = r.pairBudget(a, b, now)
		}
		v := protocol.CheckFrame(ft, body, a.DiscoKey[:], first, info, live, &budget, now.UnixMilli())
		if v.Action == "drop" {
			r.stats.Drops[v.Reason]++
		}
		r.mu.Unlock()
		if v.Action == "close" {
			return 0, c.refuse(v.Reason, fmt.Errorf("%w: region envelope %s", protocol.ErrInvalid, v.Reason))
		}
		if v.Action == "drop" {
			continue
		}
		if first {
			if err := c.admit(source); err != nil {
				return 0, err
			}
		}
		c.pending = append(header[:], body...)
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

// Disconnect closes admitted and pending device connections for k outside
// internal locks. Withdraw enrollment separately to refuse future Serve.
func (r *Region) Disconnect(k protocol.NodeKey) {
	r.mu.Lock()
	var conns []*regionConn
	for c := range r.all {
		if c == r.connections[k] || !c.local && c.p.NodeKey == k {
			conns = append(conns, c)
		}
	}
	delete(r.connections, k)
	r.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

type regionForwarderAdapter struct{ Forwarder }

func (f regionForwarderAdapter) String() string { return "region forwarder" }

func (f regionForwarderAdapter) ForwardPacket(src, dst key.NodePublic, payload derp.LoanedBytes) error {
	// The pinned fork deliberately exposes LoanedBytes without slice access.
	return f.Forwarder.ForwardPacket(regionProtocolKey(src), regionProtocolKey(dst), payload.Clone())
}

// AddForwarder registers a comparable forwarder for dst. Repeated registration
// is idempotent; a local connection takes priority over a remote forwarder.
func (r *Region) AddForwarder(dst protocol.NodeKey, f Forwarder) {
	r.server.AddPacketForwarder(regionTransportKey(dst), regionForwarderAdapter{f})
}

// RemoveForwarder removes the exact comparable registration. An absent
// registration is a no-op and other forwarders for the same key remain.
func (r *Region) RemoveForwarder(dst protocol.NodeKey, f Forwarder) {
	r.server.RemovePacketForwarder(regionTransportKey(dst), regionForwarderAdapter{f})
}

// Deliver validates a forwarded discovery payload against the receiver's live
// directory and normalized pair budget. Refusals return an error and count a
// drop without closing the shared delivery client or affecting other pairs.
// Acceptance injects a ForwardPacket; DERP never forwards it to another region.
func (r *Region) Deliver(src, dst protocol.NodeKey, payload []byte) error {
	a, b, live := r.pair(context.Background(), src, dst)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	reason := ""
	switch {
	case len(payload) > 1280 || len(payload) < 78:
		reason = "size"
	case a.NodeKey.IsZero():
		reason = "unbound_sender"
	case !live:
		reason = "unknown_pair"
	}
	if reason == "" {
		body := make([]byte, 32+len(payload))
		copy(body, dst[:])
		copy(body[32:], payload)
		now := r.o.Clock()
		// Only the pair state is shared here; one device cannot spend another's
		// connection allowance through the process-wide delivery transport.
		budget := protocol.Budget{Limits: r.o.Budget.Limits, Pair: r.pairBudget(a, b, now)}
		v := protocol.CheckFrame(byte(derp.FrameSendPacket), body, a.DiscoKey[:], false, "", true, &budget, now.UnixMilli())
		if v.Action != "accept" {
			switch v.Reason {
			case "sender":
				reason = "unbound_sender"
			case "disco":
				reason = "type"
			default:
				reason = v.Reason
			}
		}
	}
	if reason != "" {
		r.stats.Drops[reason]++
	}
	r.mu.Unlock()
	if reason != "" {
		return fmt.Errorf("%w: inbound envelope %s", protocol.ErrInvalid, reason)
	}
	if err := r.delivery.ForwardPacket(regionTransportKey(src), regionTransportKey(dst), derp.LoanBytes(payload)); err != nil {
		return fmt.Errorf("inbound delivery: %w", err)
	}
	return nil
}

// Stats copies counters and maps; callers can mutate the snapshot safely.
func (r *Region) Stats() RegionStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	stats := r.stats
	stats.Connections = len(r.connections)
	stats.Drops = maps.Clone(stats.Drops)
	stats.Closes = maps.Clone(stats.Closes)
	return stats
}

// Close idempotently refuses new streams and delivery, closes all pending and
// admitted streams, then waits for DERP shutdown. Transport errors are returned.
func (r *Region) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		conns := make([]*regionConn, 0, len(r.all))
		for c := range r.all {
			conns = append(conns, c)
		}
		r.mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
		_ = r.deliveryConn.Close()
		r.closeErr = r.server.Close()
		<-r.deliveryDone
	})
	return r.closeErr
}

// lookupAdmission waits for the one coalesced read started or joined by Lookup.
// It leaves Changed to its single reader and never retries an unavailable read.
func (d *Directory) lookupAdmission(ctx context.Context, k protocol.NodeKey) (PeerEntry, error) {
	if p, ok := d.Lookup(ctx, k); ok {
		return p, nil
	}
	d.mu.Lock()
	if read := d.pending[k]; read != nil {
		if read.done == nil {
			read.done = make(chan struct{})
		}
		done := read.done
		d.mu.Unlock()
		select {
		case <-ctx.Done():
			return PeerEntry{}, ctx.Err()
		case <-done:
		}
		d.mu.Lock()
	}
	defer d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return PeerEntry{}, err
	}
	// A shared read can finish at the deadline before ctx.Err is published.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return PeerEntry{}, context.DeadlineExceeded
	}
	now := d.o.Clock()
	if e := d.entries[k]; e != nil {
		entry := e.Value.(*cacheEntry)
		if entry.peer != nil && now.Before(entry.peer.Expires) {
			d.lru.MoveToFront(e)
			return clonePeer(*entry.peer), nil
		}
		if entry.peer == nil && now.Before(entry.missUntil) {
			return PeerEntry{}, ErrUnauthorized
		}
	}
	return PeerEntry{}, ErrUnavailable
}
