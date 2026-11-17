package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/darthShadow/shunpike/coordination/protocol"
)

func node(n byte) protocol.NodeKey   { return protocol.NodeKey{n} }
func disco(n byte) protocol.DiscoKey { return protocol.DiscoKey{n} }
func endpoint(n byte) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, n}), 1234)
}
func registration(n byte) protocol.Registration {
	return protocol.Registration{NodeKey: node(n), DiscoKey: disco(n), Endpoints: []netip.AddrPort{endpoint(n)}}
}
func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func newTestServer(t *testing.T, st Store, o Options) *Server {
	t.Helper()
	o.Store = st
	s, err := New(o)
	requireNoError(t, err)
	return s
}
func enroll(t *testing.T, s *Server, account string, n byte, expiry time.Time) Principal {
	t.Helper()
	p := Principal{Ref: DeviceRef{Account: AccountID(account), Device: DeviceID(fmt.Sprint(n))}, NodeKey: node(n), Expires: expiry}
	_, err := s.Enroll(context.Background(), p.Ref, p.NodeKey, []byte("direct_only"), expiry)
	requireNoError(t, err)
	return p
}
func addHost(t *testing.T, st Store, n byte, expiry, now time.Time) HostEntry {
	t.Helper()
	h := HostEntry{Label: fmt.Sprintf("host-%d", n), NodeKey: node(n), DiscoKey: disco(n), Endpoints: []netip.AddrPort{endpoint(n)}, PresenceExpires: expiry}
	requireNoError(t, st.PutHost(context.Background(), h, now))
	return h
}
func snapshot(t *testing.T, s *Server, p Principal) protocol.Netmap {
	t.Helper()
	m, err := s.Netmap(context.Background(), p, "")
	requireNoError(t, err)
	return m
}

type netmapResult struct {
	m   protocol.Netmap
	err error
}

func holdNetmap(s *Server, ctx context.Context, p Principal, version string) <-chan netmapResult {
	ch := make(chan netmapResult, 1)
	go func() { m, err := s.Netmap(ctx, p, version); ch <- netmapResult{m, err} }()
	return ch
}
func assertHeld(t *testing.T, ch <-chan netmapResult) {
	t.Helper()
	synctest.Wait()
	select {
	case r := <-ch:
		t.Fatalf("netmap returned before Hold: %+v %v", r.m, r.err)
	default:
	}
}
func awaitNetmap(t *testing.T, ch <-chan netmapResult) protocol.Netmap {
	t.Helper()
	select {
	case r := <-ch:
		requireNoError(t, r.err)
		return r.m
	case <-time.After(time.Second):
		t.Fatal("netmap did not return within 1 s")
		return protocol.Netmap{}
	}
}
func advance(d time.Duration) { <-time.After(d) }

func TestEnrollDeviceLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := NewMemoryStore()
		s := newTestServer(t, st, Options{Clock: time.Now})
		now := time.Now()
		for i := byte(1); i <= 32; i++ {
			expiry := now.Add(time.Hour)
			if i == 1 {
				expiry = now.Add(time.Second)
			}
			enroll(t, s, "a", i, expiry)
		}
		ref := DeviceRef{"a", "33"}
		if _, err := s.Enroll(t.Context(), ref, node(33), nil, now.Add(time.Hour)); !errors.Is(err, ErrDeviceLimit) {
			t.Fatalf("33rd enrollment: %v", err)
		}
		advance(time.Second)
		_, err := s.Enroll(t.Context(), ref, node(33), nil, now.Add(time.Hour))
		requireNoError(t, err)
	})
}
func TestEnrollNodeKeyConflict(t *testing.T) {
	st := NewMemoryStore()
	s := newTestServer(t, st, Options{})
	p := enroll(t, s, "a", 1, time.Now().Add(time.Hour))
	if _, err := s.Enroll(t.Context(), DeviceRef{"b", "other"}, p.NodeKey, nil, p.Expires); !errors.Is(err, ErrNodeKeyConflict) {
		t.Fatalf("cross-account enrollment: %v", err)
	}
}
func TestRegisterRefusesOtherNodeKey(t *testing.T) {
	st := NewMemoryStore()
	s := newTestServer(t, st, Options{})
	p := enroll(t, s, "a", 1, time.Now().Add(time.Hour))
	if err := s.Register(t.Context(), p, registration(2)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("body key differs: %v", err)
	}
	d, err := st.Device(t.Context(), p.Ref, time.Now())
	requireNoError(t, err)
	if d.Registration != nil {
		t.Fatal("unauthorized registration persisted")
	}
}

type switchStore struct {
	Store
	mu      sync.RWMutex
	current Store
}

func (s *switchStore) Device(ctx context.Context, ref DeviceRef, now time.Time) (Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current.Device(ctx, ref, now)
}
func TestAuthorizeAfterStoreLoss(t *testing.T) {
	original := NewMemoryStore()
	st := &switchStore{Store: original, current: original}
	s := newTestServer(t, st, Options{})
	p := enroll(t, s, "a", 1, time.Now().Add(time.Hour))
	requireNoError(t, s.Register(t.Context(), p, registration(1)))
	st.mu.Lock()
	st.current = NewMemoryStore()
	st.mu.Unlock()
	if err := s.Register(t.Context(), p, registration(1)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Register after store loss: %v", err)
	}
	if _, err := s.Netmap(t.Context(), p, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Netmap after store loss: %v", err)
	}
}
func TestNetmapShowsHostsOnly(t *testing.T) {
	st := NewMemoryStore()
	s := newTestServer(t, st, Options{Regions: []protocol.Region{{ID: 3, Code: "one", URL: "https://example.org/signal"}}})
	expiry := time.Now().Add(time.Hour)
	p1 := enroll(t, s, "a", 1, expiry)
	p2 := enroll(t, s, "b", 2, expiry)
	requireNoError(t, s.Register(t.Context(), p1, registration(1)))
	requireNoError(t, s.Register(t.Context(), p2, registration(2)))
	addHost(t, st, 100, expiry, time.Now())
	addHost(t, st, 101, expiry, time.Now())
	for _, p := range []Principal{p1, p2} {
		m := snapshot(t, s, p)
		if len(m.Hosts) != 2 || len(m.Regions) != 1 || m.LeaseSeconds != 90 || m.RefreshSeconds != 30 {
			t.Fatalf("netmap: %+v", m)
		}
		for _, h := range m.Hosts {
			if h.NodeKey != node(100) && h.NodeKey != node(101) {
				t.Fatalf("device leaked: %+v", h)
			}
			if h.HomeRegion != 3 {
				t.Fatalf("home region=%d want 3", h.HomeRegion)
			}
		}
		requireNoError(t, m.Validate())
	}
}
func TestNetmapLongPoll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := NewMemoryStore()
		s := newTestServer(t, st, Options{Clock: time.Now})
		p := enroll(t, s, "a", 1, time.Now().Add(time.Hour))
		requireNoError(t, s.Register(t.Context(), p, registration(1)))
		h := addHost(t, st, 100, time.Now().Add(time.Hour), time.Now())
		m := snapshot(t, s, p)
		held := holdNetmap(s, t.Context(), p, m.Version)
		assertHeld(t, held)
		advance(24 * time.Second)
		assertHeld(t, held)
		advance(time.Second)
		got := awaitNetmap(t, held)
		if got.Version != m.Version {
			t.Fatal("unchanged hold changed version")
		}
		held = holdNetmap(s, t.Context(), p, m.Version)
		assertHeld(t, held)
		h.Endpoints = []netip.AddrPort{endpoint(99)}
		requireNoError(t, s.PutHost(t.Context(), h))
		got = awaitNetmap(t, held)
		if got.Version == m.Version {
			t.Fatal("host change did not change version")
		}
		// Run also observes host writes made through another store user.
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- s.Run(ctx) }()
		synctest.Wait()
		held = holdNetmap(s, t.Context(), p, got.Version)
		assertHeld(t, held)
		h.Endpoints = []netip.AddrPort{endpoint(98)}
		requireNoError(t, st.PutHost(t.Context(), h, time.Now()))
		advance(5 * time.Second)
		got = awaitNetmap(t, held)
		if got.Hosts[0].Endpoints[0] != endpoint(98) {
			t.Fatalf("reconciled hosts: %+v", got.Hosts)
		}
		cancel()
		requireNoError(t, <-done)
	})
}
func TestPutHostWakesOnlyOnChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := NewMemoryStore()
		s := newTestServer(t, st, Options{Clock: time.Now})
		p := enroll(t, s, "a", 1, time.Now().Add(time.Hour))
		requireNoError(t, s.Register(t.Context(), p, registration(1)))
		h := HostEntry{Label: "host-100", NodeKey: node(100), DiscoKey: disco(100), Endpoints: []netip.AddrPort{endpoint(100)}, Origin: "origin-a"}
		m := snapshot(t, s, p)
		held := holdNetmap(s, t.Context(), p, m.Version)
		assertHeld(t, held)
		requireNoError(t, s.PutHost(t.Context(), h))
		if got := awaitNetmap(t, held); len(got.Hosts) != 1 {
			t.Fatalf("new host did not wake with the host: %+v", got)
		}
		m = snapshot(t, s, p)
		held = holdNetmap(s, t.Context(), p, m.Version)
		assertHeld(t, held)
		for range 2 {
			requireNoError(t, s.PutHost(t.Context(), h))
			assertHeld(t, held)
			advance(10 * time.Second)
		}
		// The renewed presence outlives the first deadline.
		advance(70 * time.Second)
		if got := snapshot(t, s, p); len(got.Hosts) != 1 || got.Version != m.Version {
			t.Fatalf("renewed host view: %+v", got)
		}
		for name, change := range map[string]func(*HostEntry){
			"node key":  func(h *HostEntry) { h.NodeKey = node(101) },
			"disco key": func(h *HostEntry) { h.DiscoKey = disco(101) },
			"endpoints": func(h *HostEntry) { h.Endpoints = []netip.AddrPort{endpoint(101)} },
			"origin":    func(h *HostEntry) { h.Origin = "origin-b" },
		} {
			m = snapshot(t, s, p)
			held = holdNetmap(s, t.Context(), p, m.Version)
			assertHeld(t, held)
			change(&h)
			requireNoError(t, s.PutHost(t.Context(), h))
			if got := awaitNetmap(t, held); got.Version == m.Version {
				t.Fatalf("%s change did not change the view", name)
			}
		}
	})
}
func TestServerOptionsHoldBelowClientTimeout(t *testing.T) {
	for _, hold := range []time.Duration{25 * time.Second, 34 * time.Second, 35 * time.Second, 36 * time.Second} {
		t.Run(hold.String(), func(t *testing.T) {
			_, err := New(Options{Store: NewMemoryStore(), Hold: hold})
			if hold < protocol.NetmapRequestTimeout && err != nil {
				t.Fatalf("valid hold refused: %v", err)
			}
			if hold >= protocol.NetmapRequestTimeout && err == nil {
				t.Fatal("unsafe hold accepted")
			}
		})
	}
}

type hostReadStore struct {
	Store
	read chan struct{}
}

func (s *hostReadStore) Hosts(ctx context.Context, now time.Time) ([]HostEntry, error) {
	hs, err := s.Store.Hosts(ctx, now)
	select {
	case s.read <- struct{}{}:
	default:
	}
	return hs, err
}
func TestSetConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint netip.AddrPort
	}{
		{"zero-endpoint", netip.AddrPort{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := NewMemoryStore()
			s := newTestServer(t, st, Options{})
			p := enroll(t, s, "a", 1, time.Now().Add(time.Hour))
			requireNoError(t, s.Register(t.Context(), p, registration(1)))
			h := addHost(t, st, 100, time.Now().Add(time.Hour), time.Now())
			c := protocol.Confirmation{Peer: p.NodeKey, DiscoKey: disco(1), Endpoint: tc.endpoint}
			if err := s.SetConfirmation(t.Context(), h.Label, c); !errors.Is(err, protocol.ErrInvalid) {
				t.Errorf("SetConfirmation error = %v, want protocol.ErrInvalid", err)
			}
			requireNoError(t, snapshot(t, s, p).Validate())
		})
	}
}

func TestConfirmationWakesHeldNetmap(t *testing.T) {
	st := &hostReadStore{Store: NewMemoryStore(), read: make(chan struct{}, 1)}
	s := newTestServer(t, st, Options{})
	p := enroll(t, s, "a", 1, time.Now().Add(time.Hour))
	requireNoError(t, s.Register(t.Context(), p, registration(1)))
	h := addHost(t, st, 100, time.Now().Add(time.Hour), time.Now())
	m := snapshot(t, s, p)
	<-st.read
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	held := holdNetmap(s, ctx, p, m.Version)
	<-st.read
	c := protocol.Confirmation{Peer: p.NodeKey, DiscoKey: disco(1), Endpoint: endpoint(1)}
	start := time.Now()
	requireNoError(t, s.SetConfirmation(t.Context(), h.Label, c))
	got := awaitNetmap(t, held)
	if time.Since(start) >= time.Second || len(got.Hosts) != 1 || got.Hosts[0].Confirmation == nil || *got.Hosts[0].Confirmation != c {
		t.Fatalf("confirmation wake: %+v", got)
	}
	c.DiscoKey = disco(2)
	requireNoError(t, s.SetConfirmation(t.Context(), h.Label, c))
	got = snapshot(t, s, p)
	if got.Hosts[0].Confirmation != nil {
		t.Fatal("old disco key confirmation visible")
	}
}
func TestConfirmationRenewalNoWake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := NewMemoryStore()
		s := newTestServer(t, st, Options{Clock: time.Now})
		p := enroll(t, s, "a", 1, time.Now().Add(time.Hour))
		requireNoError(t, s.Register(t.Context(), p, registration(1)))
		h := addHost(t, st, 100, time.Now().Add(time.Hour), time.Now())
		c := protocol.Confirmation{Peer: p.NodeKey, DiscoKey: disco(1), Endpoint: endpoint(1)}
		requireNoError(t, s.SetConfirmation(t.Context(), h.Label, c))
		version := snapshot(t, s, p).Version
		for range 12 {
			held := holdNetmap(s, t.Context(), p, version)
			assertHeld(t, held)
			requireNoError(t, s.Register(t.Context(), p, registration(1)))
			// Register wakes the device; begin a new hold for the renewal assertion.
			awaitNetmap(t, held)
			held = holdNetmap(s, t.Context(), p, version)
			assertHeld(t, held)
			requireNoError(t, s.SetConfirmation(t.Context(), h.Label, c))
			assertHeld(t, held)
			advance(25 * time.Second)
			got := awaitNetmap(t, held)
			if got.Version != version || got.Hosts[0].Confirmation == nil {
				t.Fatalf("renewal changed view: %+v", got)
			}
			advance(5 * time.Second)
		}
		// Last renewal was at 330 s. Presence registration has the same deadline.
		advance(59 * time.Second)
		requireNoError(t, s.Register(t.Context(), p, registration(1)))
		if snapshot(t, s, p).Hosts[0].Confirmation == nil {
			t.Fatal("confirmation expired before 90 s")
		}
		advance(time.Second)
		if snapshot(t, s, p).Hosts[0].Confirmation != nil {
			t.Fatal("confirmation remained at expiry")
		}
		requireNoError(t, s.SetConfirmation(t.Context(), h.Label, c))
		m := snapshot(t, s, p)
		held := holdNetmap(s, t.Context(), p, m.Version)
		assertHeld(t, held)
		c.Endpoint = endpoint(2)
		requireNoError(t, s.SetConfirmation(t.Context(), h.Label, c))
		got := awaitNetmap(t, held)
		if got.Hosts[0].Confirmation == nil || got.Hosts[0].Confirmation.Endpoint != c.Endpoint {
			t.Fatal("endpoint change did not wake with new identity")
		}
	})
}
func TestNetmapVersionAcrossInstances(t *testing.T) {
	st := NewMemoryStore()
	s := newTestServer(t, st, Options{})
	p := enroll(t, s, "a", 1, time.Now().Add(time.Hour))
	requireNoError(t, s.Register(t.Context(), p, registration(1)))
	addHost(t, st, 100, time.Now().Add(time.Hour), time.Now())
	other := newTestServer(t, st, Options{})
	if snapshot(t, s, p).Version != snapshot(t, other, p).Version {
		t.Fatal("versions depend on server instance")
	}
}
func TestExpiredPresenceHidden(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := NewMemoryStore()
		s := newTestServer(t, st, Options{Clock: time.Now})
		p := enroll(t, s, "a", 1, time.Now().Add(180*time.Second))
		requireNoError(t, s.Register(t.Context(), p, registration(1)))
		addHost(t, st, 100, time.Now().Add(90*time.Second), time.Now())
		if len(snapshot(t, s, p).Hosts) != 1 {
			t.Fatal("live host absent")
		}
		advance(90 * time.Second)
		if len(snapshot(t, s, p).Hosts) != 0 {
			t.Fatal("expired host visible")
		}
		advance(90 * time.Second)
		if _, err := s.Netmap(t.Context(), p, ""); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("expired lease authorized: %v", err)
		}
	})
}
func TestWithdrawRefusesFurtherRequests(t *testing.T) {
	st := NewMemoryStore()
	s := newTestServer(t, st, Options{})
	p := enroll(t, s, "a", 1, time.Now().Add(time.Hour))
	requireNoError(t, s.Register(t.Context(), p, registration(1)))
	requireNoError(t, s.Withdraw(t.Context(), p.Ref))
	if _, err := s.Authorize(t.Context(), p); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("withdrawn authorization: %v", err)
	}
	if err := s.Register(t.Context(), p, registration(1)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("withdrawn registration: %v", err)
	}
}
