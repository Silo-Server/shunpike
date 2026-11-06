package server

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"go4.org/mem"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"

	"github.com/darthShadow/shunpike/coordination/protocol"
)

type regionFixture struct {
	ctx       context.Context
	st        Store
	s         *Server
	d         *Directory
	r         *Region
	host      key.NodePrivate
	hostDisco protocol.DiscoKey
	device    key.NodePrivate
	p         Principal
	disco     protocol.DiscoKey
}

func regionNode(k key.NodePrivate) protocol.NodeKey  { return regionProtocolKey(k.Public()) }
func regionPublic(k protocol.NodeKey) key.NodePublic { return key.NodePublicFromRaw32(mem.B(k[:])) }

func newRegionFixture(t *testing.T) *regionFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	f := &regionFixture{ctx: ctx, st: NewMemoryStore(), host: key.NewNode(), device: key.NewNode(), hostDisco: disco(91), disco: disco(92)}
	f.s = newTestServer(t, f.st, Options{})
	f.d = NewDirectory(f.st, DirectoryOptions{})
	f.p = f.addDevice(t, f.device, f.disco, "first")
	requireNoError(t, f.st.PutHost(ctx, HostEntry{Label: "host", NodeKey: regionNode(f.host), DiscoKey: f.hostDisco, PresenceExpires: time.Now().Add(time.Hour)}, time.Now()))
	f.warm(t, regionNode(f.host))
	var err error
	f.r, err = NewRegion(RegionOptions{Server: f.s, Directory: f.d})
	requireNoError(t, err)
	t.Cleanup(func() { requireNoError(t, f.r.Close()) })
	return f
}

func (f *regionFixture) addDevice(t *testing.T, k key.NodePrivate, dk protocol.DiscoKey, name string) Principal {
	t.Helper()
	p := Principal{Ref: DeviceRef{"account", DeviceID(name)}, NodeKey: regionNode(k), Expires: time.Now().Add(time.Hour)}
	_, err := f.s.Enroll(f.ctx, p.Ref, p.NodeKey, nil, p.Expires)
	requireNoError(t, err)
	requireNoError(t, f.s.Register(f.ctx, p, protocol.Registration{NodeKey: p.NodeKey, DiscoKey: dk}))
	f.warm(t, p.NodeKey)
	return p
}

func (f *regionFixture) warm(t *testing.T, k protocol.NodeKey) {
	t.Helper()
	for {
		if _, ok := f.d.Lookup(f.ctx, k); ok {
			return
		}
		select {
		case <-f.d.Changed():
		case <-f.ctx.Done():
			t.Fatal("directory did not load peer:", f.ctx.Err())
		}
	}
}

func regionPacket(dk protocol.DiscoKey) []byte {
	b := make([]byte, 78)
	copy(b, []byte{'T', 'S', 0xf0, 0x9f, 0x92, 0xac})
	copy(b[6:38], dk[:])
	return b
}

type regionReader struct {
	messages chan derp.ReceivedMessage
	closed   chan error
}

func readRegionClient(recv func() (derp.ReceivedMessage, error)) *regionReader {
	r := &regionReader{messages: make(chan derp.ReceivedMessage, 128), closed: make(chan error, 1)}
	go func() {
		for {
			m, err := recv()
			if err != nil {
				r.closed <- err
				return
			}
			if p, ok := m.(derp.ReceivedPacket); ok {
				p.Data = bytes.Clone(p.Data)
				m = p
			}
			r.messages <- m
		}
	}()
	return r
}

func (r *regionReader) packet(t *testing.T, ctx context.Context, src protocol.NodeKey, payload []byte) {
	t.Helper()
	for {
		select {
		case m := <-r.messages:
			if p, ok := m.(derp.ReceivedPacket); ok {
				if p.Source != regionPublic(src) || !bytes.Equal(p.Data, payload) {
					t.Fatalf("packet = %+v, want source %v payload %x", p, src, payload)
				}
				return
			}
		case err := <-r.closed:
			t.Fatal("client closed before packet:", err)
		case <-ctx.Done():
			t.Fatal("packet missing:", ctx.Err())
		}
	}
}

func (r *regionReader) waitClosed(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case err := <-r.closed:
		if err == nil {
			t.Fatal("receive loop ended without a transport error")
		}
	case <-ctx.Done():
		t.Fatal("connection remains open:", ctx.Err())
	}
}

func (f *regionFixture) pipe(t *testing.T, p Principal, wrap func(net.Conn) net.Conn) (net.Conn, <-chan error) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close() })
	if wrap != nil {
		b = wrap(b)
	}
	done := make(chan error, 1)
	go func() { done <- f.r.Serve(f.ctx, b, p) }()
	return a, done
}

func (f *regionFixture) client(t *testing.T, k key.NodePrivate, p Principal, wrap func(net.Conn) net.Conn) (*derp.Client, *regionReader) {
	t.Helper()
	nc, _ := f.pipe(t, p, wrap)
	c, err := derp.NewClient(k, nc, bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc)), t.Logf)
	requireNoError(t, err)
	m, err := c.Recv()
	requireNoError(t, err)
	if _, ok := m.(derp.ServerInfoMessage); !ok {
		t.Fatalf("first message = %T, want ServerInfo", m)
	}
	return c, readRegionClient(c.Recv)
}

func (f *regionFixture) local(t *testing.T) (*derp.Client, *regionReader) {
	return f.localKey(t, f.host)
}

func (f *regionFixture) localKey(t *testing.T, k key.NodePrivate) (*derp.Client, *regionReader) {
	t.Helper()
	nc, err := f.r.DialLocal(f.ctx)
	requireNoError(t, err)
	t.Cleanup(func() { _ = nc.Close() })
	c, err := derp.NewClient(k, nc, bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc)), t.Logf)
	requireNoError(t, err)
	_, err = c.Recv()
	requireNoError(t, err)
	return c, readRegionClient(c.Recv)
}

func regionBarrier(t *testing.T, ctx context.Context, c *derp.Client, rd *regionReader) {
	t.Helper()
	ping := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	requireNoError(t, c.SendPing(ping))
	for {
		select {
		case m := <-rd.messages:
			if p, ok := m.(derp.PongMessage); ok {
				if [8]byte(p) != ping {
					t.Fatalf("pong = %v", p)
				}
				return
			}
		case err := <-rd.closed:
			t.Fatal("closed before pong:", err)
		case <-ctx.Done():
			t.Fatal("pong missing:", ctx.Err())
		}
	}
}

func TestRegionFullFrameSet(t *testing.T) {
	f := newRegionFixture(t)
	hostClient, host := f.local(t)
	monitor := netmon.NewStatic()
	t.Cleanup(func() { _ = monitor.Close() })
	c, err := derphttp.NewClient(f.device, "https://region.invalid/signal", t.Logf, monitor)
	requireNoError(t, err)
	c.StreamDial = func(context.Context, string) (net.Conn, error) { nc, _ := f.pipe(t, f.p, nil); return nc, nil }
	t.Cleanup(func() { _ = c.Close() })
	requireNoError(t, c.Connect(f.ctx))
	rd := readRegionClient(c.Recv)
	c.NotePreferred(true)
	c.NotePreferred(false)
	requireNoError(t, c.Ping(f.ctx))
	requireNoError(t, c.SendPong([8]byte{8, 7, 6, 5, 4, 3, 2, 1}))
	payload := regionPacket(f.disco)
	requireNoError(t, c.Send(f.host.Public(), payload))
	host.packet(t, f.ctx, f.p.NodeKey, payload)
	reverse := regionPacket(f.hostDisco)
	requireNoError(t, hostClient.Send(f.device.Public(), reverse))
	rd.packet(t, f.ctx, regionNode(f.host), reverse)
	if stats := f.r.Stats(); len(stats.Closes) != 0 || len(stats.Drops) != 0 {
		t.Fatalf("unexpected refusals: %+v", stats)
	}
}

func TestRegionRefusesOtherClientKey(t *testing.T) {
	for _, tc := range []struct {
		name         string
		checkDecrypt bool
	}{
		{"identity", false}, {"before_decryption", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRegionFixture(t)
			var calls atomic.Int32
			open := f.r.openClientInfo
			f.r.openClientInfo = func(src key.NodePublic, ciphertext []byte) ([]byte, bool) {
				calls.Add(1)
				return open(src, ciphertext)
			}
			nc, done := f.pipe(t, f.p, nil)
			c, err := derp.NewClient(key.NewNode(), nc, bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc)), t.Logf)
			if err == nil {
				_, err = c.Recv()
			}
			if err == nil {
				t.Fatal("ClientInfo for another key was accepted")
			}
			select {
			case err := <-done:
				if !errors.Is(err, ErrUnauthorized) {
					t.Fatalf("Serve = %v, want unauthorized", err)
				}
			case <-f.ctx.Done():
				t.Fatal(f.ctx.Err())
			}
			if f.r.Stats().Connections != 0 {
				t.Fatal("refused client registered")
			}
			if tc.checkDecrypt && calls.Load() != 0 {
				t.Fatalf("OpenFrom calls = %d, want 0 for mismatched source", calls.Load())
			}
		})
	}
}

func TestRegionDropsWrongSender(t *testing.T) {
	f := newRegionFixture(t)
	_, host := f.local(t)
	c, rd := f.client(t, f.device, f.p, nil)
	requireNoError(t, c.Send(f.host.Public(), regionPacket(disco(99))))
	regionBarrier(t, f.ctx, c, rd)
	if got := f.r.Stats().Drops["sender"]; got != 1 {
		t.Fatalf("sender drops = %d, want 1", got)
	}
	payload := regionPacket(f.disco)
	requireNoError(t, c.Send(f.host.Public(), payload))
	host.packet(t, f.ctx, f.p.NodeKey, payload)
}

func TestRegionDropsDevicePair(t *testing.T) {
	f := newRegionFixture(t)
	other := key.NewNode()
	op := f.addDevice(t, other, disco(93), "second")
	_, _ = f.client(t, other, op, nil)
	c, rd := f.client(t, f.device, f.p, nil)
	requireNoError(t, c.Send(other.Public(), regionPacket(f.disco)))
	regionBarrier(t, f.ctx, c, rd)
	if got := f.r.Stats().Drops["pair"]; got != 1 {
		t.Fatalf("pair drops = %d, want 1", got)
	}
}

func TestRegionClosesMeshClientInfo(t *testing.T) {
	for _, mode := range []string{"mesh", "close_peer", "duplicate_client_info", "first_not_client_info", "zero_client_key"} {
		t.Run(mode, func(t *testing.T) {
			f := newRegionFixture(t)
			nc, done := f.pipe(t, f.p, nil)
			var opts []derp.ClientOpt
			if mode == "mesh" {
				opts = append(opts, derp.MeshKey(key.DERPMeshFromRaw32(mem.B(bytes.Repeat([]byte{1}, 32)))))
			}
			if mode == "first_not_client_info" || mode == "zero_client_key" {
				br := bufio.NewReader(nc)
				ft, size, err := derp.ReadFrameHeader(br)
				requireNoError(t, err)
				if ft != derp.FrameServerKey {
					t.Fatalf("server frame = %v", ft)
				}
				_, err = io.CopyN(io.Discard, br, int64(size))
				requireNoError(t, err)
				if mode == "zero_client_key" {
					requireNoError(t, derp.WriteFrame(bufio.NewWriter(nc), derp.FrameClientInfo, make([]byte, 72)))
				} else {
					requireNoError(t, derp.WriteFrame(bufio.NewWriter(nc), derp.FramePing, make([]byte, 8)))
				}
			} else {
				c, err := derp.NewClient(f.device, nc, bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc)), t.Logf, opts...)
				requireNoError(t, err)
				if mode == "mesh" {
					if _, err = c.Recv(); err == nil {
						t.Fatal("mesh ClientInfo accepted")
					}
				} else {
					_, err = c.Recv()
					requireNoError(t, err)
					if mode == "close_peer" {
						requireNoError(t, c.ClosePeer(f.host.Public()))
					} else {
						requireNoError(t, derp.WriteFrame(bufio.NewWriter(nc), derp.FrameClientInfo, make([]byte, 72)))
					}
					if _, err = c.Recv(); err == nil {
						t.Fatal("forbidden frame accepted")
					}
				}
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("forbidden frame ended Serve without an error")
				}
			case <-f.ctx.Done():
				t.Fatal("forbidden client remains open")
			}
			if len(f.r.Stats().Closes) != 1 {
				t.Fatalf("close counters = %v", f.r.Stats().Closes)
			}
		})
	}
}

type regionCloseObserver struct {
	net.Conn
	once  sync.Once
	check func()
}

func (c *regionCloseObserver) Close() error { c.once.Do(c.check); return c.Conn.Close() }

func TestRegionReplacesConnection(t *testing.T) {
	f := newRegionFixture(t)
	closed := make(chan bool, 1)
	_, first := f.client(t, f.device, f.p, func(nc net.Conn) net.Conn {
		return &regionCloseObserver{Conn: nc, check: func() {
			store := f.st.(*memoryStore)
			stok := store.mu.TryLock()
			if stok {
				store.mu.Unlock()
			}
			sok := f.s.mu.TryLock()
			if sok {
				f.s.mu.Unlock()
			}
			rok := f.r.mu.TryLock()
			if rok {
				f.r.mu.Unlock()
			}
			closed <- stok && sok && rok
		}}
	})
	c, rd := f.client(t, f.device, f.p, nil)
	first.waitClosed(t, f.ctx)
	select {
	case unlocked := <-closed:
		if !unlocked {
			t.Fatal("replacement closes under a store, server or region lock")
		}
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	regionBarrier(t, f.ctx, c, rd)
	if st := f.r.Stats(); st.Replaced != 1 || st.Connections != 1 {
		t.Fatalf("replacement stats = %+v", st)
	}
}

func TestRegionClosesAtExpiry(t *testing.T) {
	f := newRegionFixture(t)
	p := f.p
	p.Expires = time.Now().Add(300 * time.Millisecond)
	_, rd := f.client(t, f.device, p, nil)
	ctx, cancel := context.WithDeadline(f.ctx, p.Expires.Add(100*time.Millisecond))
	defer cancel()
	rd.waitClosed(t, ctx)
	if time.Now().Before(p.Expires) {
		t.Fatal("connection closed before principal expiry")
	}
}

func TestRegionDisconnect(t *testing.T) {
	for _, tc := range []string{"admitted_withdrawn", "before_client_info"} {
		t.Run(tc, func(t *testing.T) {
			f := newRegionFixture(t)
			_, rd := f.client(t, f.device, f.p, nil)
			if tc == "before_client_info" {
				closed := make(chan struct{}, 2)
				for range 2 {
					nc, _ := f.pipe(t, f.p, func(nc net.Conn) net.Conn {
						return &regionCloseObserver{Conn: nc, check: func() { closed <- struct{}{} }}
					})
					br := bufio.NewReader(nc)
					ft, size, err := derp.ReadFrameHeader(br)
					requireNoError(t, err)
					if ft != derp.FrameServerKey {
						t.Fatalf("first frame = %v, want ServerKey", ft)
					}
					_, err = io.CopyN(io.Discard, br, int64(size))
					requireNoError(t, err)
				}
				f.r.Disconnect(f.p.NodeKey)
				rd.waitClosed(t, f.ctx)
				ctx, cancel := context.WithTimeout(f.ctx, 250*time.Millisecond)
				defer cancel()
				for range 2 {
					select {
					case <-closed:
					case <-ctx.Done():
						t.Fatal("Disconnect left a pre-ClientInfo connection open")
					}
				}
				return
			}
			requireNoError(t, f.s.Withdraw(f.ctx, f.p.Ref))
			f.r.Disconnect(f.p.NodeKey)
			rd.waitClosed(t, f.ctx)
			nc, done := f.pipe(t, f.p, nil)
			select {
			case err := <-done:
				if !errors.Is(err, ErrUnauthorized) {
					t.Fatalf("withdrawn Serve = %v", err)
				}
			case <-f.ctx.Done():
				t.Fatal("withdrawn principal was admitted")
			}
			_, err := nc.Write([]byte{1})
			if err == nil {
				t.Fatal("withdrawn connection remains writable")
			}
		})
	}
}

type regionUnresponsiveReadStore struct {
	Store
	gate  <-chan struct{}
	reads atomic.Int32
}

func (s *regionUnresponsiveReadStore) DeviceByNodeKey(ctx context.Context, k protocol.NodeKey, now time.Time) (Device, error) {
	s.reads.Add(1)
	d, err := s.Store.DeviceByNodeKey(ctx, k, now)
	// The external read cannot return while the gate is held, even on cancel.
	// Release it only after admission ends, so a store timeout cannot end the wait.
	<-s.gate
	if ctx.Err() != nil {
		return Device{}, ctx.Err()
	}
	return d, err
}

func TestRegionAdmission(t *testing.T) {
	for _, tc := range []string{"cold_first_frame", "coalesced_pending", "timeout_device", "timeout_host", "nonblocking_frames", "shared_read_owner_cancels", "joined_read_waiter_timeout", "withdrawn_while_waiting", "preferred_before_server_info"} {
		t.Run(tc, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newRegionFixture(t)
				if tc == "preferred_before_server_info" {
					nc, err := f.r.DialLocal(f.ctx)
					requireNoError(t, err)
					ctx, cancel := context.WithTimeout(f.ctx, time.Second)
					defer cancel()
					type handshakeResult struct {
						message derp.ReceivedMessage
						err     error
					}
					result := make(chan handshakeResult, 1)
					done := make(chan struct{})
					go func() {
						defer close(done)
						// NewClient sends ClientInfo; receive only after NotePreferred is written.
						c, err := derp.NewClient(f.host, nc, bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc)), t.Logf)
						if err == nil {
							err = c.NotePreferred(true)
						}
						var message derp.ReceivedMessage
						if err == nil {
							message, err = c.Recv()
						}
						result <- handshakeResult{message, err}
					}()
					t.Cleanup(func() { _ = nc.Close(); <-done })
					select {
					case got := <-result:
						requireNoError(t, got.err)
						if _, ok := got.message.(derp.ServerInfoMessage); !ok {
							t.Fatalf("first message = %T, want ServerInfo", got.message)
						}
					case <-ctx.Done():
						t.Fatal("ServerInfo not received within 1s after ClientInfo and NotePreferred writes")
					}
					return
				}
				gate := make(chan struct{})
				st := &directoryStore{Store: f.st}
				if tc != "cold_first_frame" {
					st.release = gate
				}
				if tc == "nonblocking_frames" {
					f.d.st = st
					c, rd := f.client(t, f.device, f.p, nil)
					requireNoError(t, c.Send(regionPublic(node(114)), regionPacket(f.disco)))
					regionBarrier(t, f.ctx, c, rd)
					if got := f.r.Stats().Drops["pair"]; got != 1 {
						t.Fatalf("unknown-pair drops = %d, want 1", got)
					}
					if err := f.r.Deliver(node(115), regionNode(f.host), regionPacket(f.disco)); err == nil {
						t.Fatal("unknown inbound sender accepted")
					}
					close(gate)
					return
				}
				f.d = NewDirectory(st, DirectoryOptions{MissTTL: 37 * time.Millisecond})
				f.r.o.Directory = f.d
				if tc == "shared_read_owner_cancels" || tc == "joined_read_waiter_timeout" || tc == "withdrawn_while_waiting" {
					dial := func(ctx context.Context) (net.Conn, <-chan error, <-chan error) {
						a, b := net.Pipe()
						t.Cleanup(func() { _ = a.Close() })
						serve := make(chan error, 1)
						go func() { serve <- f.r.Serve(ctx, b, f.p) }()
						c, err := derp.NewClient(f.device, a, bufio.NewReadWriter(bufio.NewReader(a), bufio.NewWriter(a)), t.Logf)
						requireNoError(t, err)
						result := make(chan error, 1)
						go func() { _, err := c.Recv(); result <- err }()
						return a, result, serve
					}
					if tc == "shared_read_owner_cancels" {
						owner, cancel := context.WithCancel(f.ctx)
						defer cancel()
						_, first, firstServe := dial(owner)
						synctest.Wait()
						conn, second, secondServe := dial(f.ctx)
						synctest.Wait()
						cancel()
						if err := <-first; err == nil {
							t.Error("cancelled owner was admitted")
						}
						if err := <-firstServe; !errors.Is(err, context.Canceled) {
							t.Errorf("owner Serve = %v, want canceled", err)
						}
						synctest.Wait()
						close(gate)
						if err := <-second; err != nil {
							t.Errorf("second waiter refused after owner cancellation: %v", err)
						}
						requireNoError(t, conn.Close())
						if err := <-secondServe; err != nil {
							t.Errorf("second Serve = %v, want successful admission", err)
						}
						if got := st.count(); got != 1 {
							t.Fatalf("shared directory reads = %d, want 1", got)
						}
						t.Logf("shared read count = %d", st.count())
						return
					}
					if tc == "joined_read_waiter_timeout" {
						blocked := &regionUnresponsiveReadStore{Store: f.st, gate: gate}
						f.d = NewDirectory(blocked, DirectoryOptions{})
						f.r.o.Directory = f.d
						if _, ok := f.d.Lookup(context.Background(), f.p.NodeKey); ok {
							t.Fatal("cold lookup hit")
						}
						synctest.Wait()
						start := time.Now()
						_, result, serve := dial(f.ctx)
						recvErr := <-result
						elapsed := time.Since(start)
						// The read never answers before the wait ends; release only for cleanup.
						close(gate)
						serveErr := <-serve
						if recvErr == nil {
							t.Error("waiter with an unresponsive shared read was admitted")
						}
						if elapsed != 2*time.Second {
							t.Errorf("joined read wait = %v, want admissionWait (2s)", elapsed)
						}
						if !errors.Is(serveErr, context.DeadlineExceeded) {
							t.Errorf("Serve = %v, want deadline exceeded", serveErr)
						}
						if got := blocked.reads.Load(); got != 1 {
							t.Errorf("joined directory reads = %d, want 1", got)
						}
						t.Logf("waiter returned at %v before store release; reads = %d", elapsed, blocked.reads.Load())
						return
					}
					if _, ok := f.d.Lookup(context.Background(), f.p.NodeKey); ok {
						t.Fatal("cold lookup hit")
					}
					synctest.Wait()
					conn, result, serve := dial(f.ctx)
					synctest.Wait()
					select {
					case err := <-result:
						t.Fatalf("admission returned before withdrawal: %v", err)
					default:
					}
					requireNoError(t, f.s.Withdraw(f.ctx, f.p.Ref))
					close(gate)
					if err := <-result; err == nil {
						t.Error("withdrawn device admitted after wait")
					}
					requireNoError(t, conn.Close())
					if err := <-serve; !errors.Is(err, ErrUnauthorized) {
						t.Errorf("withdrawn Serve = %v, want unauthorized", err)
					}
					if got := st.count(); got != 1 {
						t.Errorf("withdrawal directory reads = %d, want 1", got)
					}
					if got := f.r.Stats().Connections; got != 0 {
						t.Errorf("withdrawn admitted connections = %d, want 0", got)
					}
					return
				}
				if tc == "cold_first_frame" {
					_, host := f.local(t)
					c, rd := f.client(t, f.device, f.p, nil)
					payload := regionPacket(f.disco)
					requireNoError(t, c.Send(f.host.Public(), payload))
					host.packet(t, f.ctx, f.p.NodeKey, payload)
					regionBarrier(t, f.ctx, c, rd)
					if got := f.r.Stats().Drops; len(got) != 0 {
						t.Fatalf("first frame dropped: %v", got)
					}
					if got := st.count(); got != 2 {
						t.Fatalf("directory reads = %d, want one per connecting key (2)", got)
					}
					return
				}
				if tc == "coalesced_pending" {
					if _, ok := f.d.Lookup(f.ctx, f.p.NodeKey); ok {
						t.Fatal("cold lookup hit")
					}
					synctest.Wait()
					nc, _ := f.pipe(t, f.p, nil)
					c, err := derp.NewClient(f.device, nc, bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc)), t.Logf)
					requireNoError(t, err)
					result := make(chan error, 1)
					go func() { _, err := c.Recv(); result <- err }()
					synctest.Wait()
					select {
					case err := <-result:
						t.Fatalf("admission returned before the shared read: %v", err)
					default:
					}
					close(gate)
					requireNoError(t, <-result)
					if got := st.count(); got != 1 {
						t.Fatalf("coalesced directory reads = %d, want 1", got)
					}
					return
				}
				var nc net.Conn
				var done <-chan error
				k := f.device
				if tc == "timeout_host" {
					var err error
					nc, err = f.r.DialLocal(f.ctx)
					requireNoError(t, err)
					t.Cleanup(func() { _ = nc.Close() })
					k = f.host
				} else {
					nc, done = f.pipe(t, f.p, nil)
				}
				start := time.Now()
				c, err := derp.NewClient(k, nc, bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc)), t.Logf)
				requireNoError(t, err)
				if _, err = c.Recv(); err == nil {
					t.Fatal("admission with blocked storage succeeded")
				}
				elapsed := time.Since(start)
				if elapsed != 2*time.Second {
					t.Fatalf("admission wait = %v, want 2s independent of MissTTL", elapsed)
				}
				t.Logf("admission wait = %v; directory MissTTL = %v", elapsed, f.d.o.MissTTL)
				if done != nil {
					if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("Serve error = %v, want deadline exceeded", err)
					}
				}
				if got := st.count(); got != 1 {
					t.Fatalf("timeout directory reads = %d, want 1", got)
				}
				if got := f.r.Stats(); got.Connections != 0 || got.Closes["client_info"] != 1 {
					t.Fatalf("timed-out admission stats = %+v", got)
				}
			})
		})
	}
}

func TestRegionBudgetDropsThenCloses(t *testing.T) {
	f := newRegionFixture(t)
	now := time.Now()
	f.r.o.Clock = func() time.Time { return now }
	c, rd := f.client(t, f.device, f.p, nil)
	for i := 0; i < 23; i++ {
		requireNoError(t, c.Send(f.host.Public(), regionPacket(f.disco)))
	}
	rd.waitClosed(t, f.ctx)
	st := f.r.Stats()
	if st.Drops["budget"] != 2 || st.Closes["budget"] != 1 {
		t.Fatalf("overrun stats = %+v", st)
	}
}

func TestDeliverInboundEnvelope(t *testing.T) {
	f := newRegionFixture(t)
	now := time.Now()
	f.r.o.Clock = func() time.Time { return now }
	_, host := f.local(t)
	hk := regionNode(f.host)
	for _, tc := range []struct {
		name     string
		src, dst protocol.NodeKey
		payload  []byte
	}{
		{"unbound_sender", node(111), hk, regionPacket(f.disco)},
		{"unknown_pair", f.p.NodeKey, node(112), regionPacket(f.disco)},
		{"unbound_sender", f.p.NodeKey, hk, regionPacket(disco(99))},
		{"size", f.p.NodeKey, hk, make([]byte, 1281)},
	} {
		if err := f.r.Deliver(tc.src, tc.dst, tc.payload); err == nil {
			t.Fatalf("%s accepted", tc.name)
		}
	}
	payload := regionPacket(f.disco)
	for i := 0; i < 20; i++ {
		requireNoError(t, f.r.Deliver(f.p.NodeKey, hk, payload))
		host.packet(t, f.ctx, f.p.NodeKey, payload)
	}
	for i := 0; i < 3; i++ {
		if err := f.r.Deliver(f.p.NodeKey, hk, payload); err == nil {
			t.Fatal("over-budget delivery accepted")
		}
	}
	other := key.NewNode()
	op := f.addDevice(t, other, disco(93), "second")
	good := regionPacket(disco(93))
	requireNoError(t, f.r.Deliver(op.NodeKey, hk, good))
	host.packet(t, f.ctx, op.NodeKey, good)
	st := f.r.Stats()
	if st.Drops["unbound_sender"] != 2 || st.Drops["unknown_pair"] != 1 || st.Drops["size"] != 1 || st.Drops["budget"] != 3 {
		t.Fatalf("inbound drops = %+v", st)
	}
}

type regionForwarded struct {
	src, dst protocol.NodeKey
	payload  []byte
}
type regionForwarder struct{ packets chan regionForwarded }

func (f *regionForwarder) ForwardPacket(src, dst protocol.NodeKey, payload []byte) error {
	f.packets <- regionForwarded{src, dst, bytes.Clone(payload)}
	return nil
}

func TestForwarderRegistration(t *testing.T) {
	f := newRegionFixture(t)
	forwarder := &regionForwarder{packets: make(chan regionForwarded, 4)}
	hk := regionNode(f.host)
	f.r.AddForwarder(hk, forwarder)
	f.r.AddForwarder(hk, forwarder)
	c, rd := f.client(t, f.device, f.p, nil)
	payload := regionPacket(f.disco)
	requireNoError(t, c.Send(f.host.Public(), payload))
	select {
	case got := <-forwarder.packets:
		if got.src != f.p.NodeKey || got.dst != hk || !bytes.Equal(got.payload, payload) {
			t.Fatalf("forwarded = %+v", got)
		}
	case <-f.ctx.Done():
		t.Fatal("forwarder not called")
	}
	f.r.RemoveForwarder(hk, forwarder)
	requireNoError(t, c.Send(f.host.Public(), payload))
	regionBarrier(t, f.ctx, c, rd)
	select {
	case <-forwarder.packets:
		t.Fatal("removed forwarder called")
	default:
	}
	f.r.AddForwarder(hk, forwarder)
	observer := key.NewNode()
	requireNoError(t, f.st.PutHost(f.ctx, HostEntry{Label: "observer", NodeKey: regionNode(observer), DiscoKey: disco(94), PresenceExpires: time.Now().Add(time.Hour)}, time.Now()))
	f.warm(t, regionNode(observer))
	_, received := f.localKey(t, observer)
	requireNoError(t, f.r.Deliver(f.p.NodeKey, hk, payload))
	// This receipt orders the earlier remote delivery while its destination
	// still has only a forwarder. A local receiver cannot mask re-forwarding.
	requireNoError(t, f.r.Deliver(f.p.NodeKey, regionNode(observer), payload))
	received.packet(t, f.ctx, f.p.NodeKey, payload)
	select {
	case <-forwarder.packets:
		t.Fatal("inbound packet forwarded again")
	default:
	}
}

func TestRegionLocalAdmissionAndClose(t *testing.T) {
	f := newRegionFixture(t)
	nc, err := f.r.DialLocal(f.ctx)
	requireNoError(t, err)
	c, err := derp.NewClient(f.device, nc, bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc)), t.Logf)
	requireNoError(t, err)
	if _, err := c.Recv(); err == nil {
		t.Fatal("device admitted as local host")
	}
	requireNoError(t, nc.Close())
	_, rd := f.local(t)
	requireNoError(t, f.r.Close())
	rd.waitClosed(t, f.ctx)
	if _, err := f.r.DialLocal(f.ctx); err == nil {
		t.Fatal("dial after close accepted")
	}
	if err := f.r.Deliver(f.p.NodeKey, regionNode(f.host), regionPacket(f.disco)); err == nil {
		t.Fatal("delivery after close accepted")
	}
	if got := f.r.Stats().Connections; got != 0 {
		t.Fatalf("connections after close = %d", got)
	}
}
