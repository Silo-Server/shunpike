package server

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/darthShadow/shunpike/coordination/protocol"
)

type directoryStore struct {
	Store
	mu           sync.Mutex
	reads, lists int
	down         bool
	release      <-chan struct{}
}

func (s *directoryStore) DeviceByNodeKey(ctx context.Context, k protocol.NodeKey, now time.Time) (Device, error) {
	s.mu.Lock()
	s.reads++
	down := s.down
	release := s.release
	s.mu.Unlock()
	if down {
		return Device{}, ErrUnavailable
	}
	d, err := s.Store.DeviceByNodeKey(ctx, k, now)
	if release != nil {
		select {
		case <-ctx.Done():
			return Device{}, ctx.Err()
		case <-release:
		}
	}
	return d, err
}
func (s *directoryStore) ListDevices(ctx context.Context, a AccountID, now time.Time) ([]Device, error) {
	s.mu.Lock()
	s.lists++
	down := s.down
	s.mu.Unlock()
	if down {
		return nil, ErrUnavailable
	}
	return s.Store.ListDevices(ctx, a, now)
}
func (s *directoryStore) Hosts(ctx context.Context, now time.Time) ([]HostEntry, error) {
	s.mu.Lock()
	down := s.down
	s.mu.Unlock()
	if down {
		return nil, ErrUnavailable
	}
	return s.Store.Hosts(ctx, now)
}
func (s *directoryStore) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.reads }
func (s *directoryStore) setDown()   { s.mu.Lock(); defer s.mu.Unlock(); s.down = true }
func directoryDevice(t *testing.T, st Store, n byte, expiry, now time.Time) Device {
	t.Helper()
	d := Device{Ref: DeviceRef{"a", DeviceID(node(n).String())}, NodeKey: node(n), Policy: []byte("direct_only"), LeaseExpires: expiry}
	_, err := st.PutDevice(t.Context(), d, 32, now)
	requireNoError(t, err)
	requireNoError(t, st.PutRegistration(t.Context(), d.Ref, registration(n), expiry, now))
	return d
}
func directoryHit(t *testing.T, d *Directory, k protocol.NodeKey) PeerEntry {
	t.Helper()
	p, ok := d.Lookup(t.Context(), k)
	if !ok {
		synctest.Wait()
		p, ok = d.Lookup(t.Context(), k)
	}
	if !ok {
		t.Fatal("live entry was not loaded")
	}
	return p
}
func takeChanged(t *testing.T, d *Directory) {
	t.Helper()
	synctest.Wait()
	select {
	case <-d.Changed():
	default:
		t.Fatal("missing Changed event")
	}
}
func noChanged(t *testing.T, d *Directory) {
	t.Helper()
	synctest.Wait()
	select {
	case <-d.Changed():
		t.Fatal("unexpected Changed event")
	default:
	}
}
func runDirectory(t *testing.T, d *Directory) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	synctest.Wait()
	return func() { cancel(); requireNoError(t, <-done) }
}

func TestDirectoryMissCoalesced(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		st := &directoryStore{Store: NewMemoryStore(), release: release}
		d := NewDirectory(st, DirectoryOptions{Clock: time.Now})
		var wg sync.WaitGroup
		for range 100 {
			wg.Go(func() {
				if _, ok := d.Lookup(t.Context(), node(1)); ok {
					t.Error("unknown key hit")
				}
			})
		}
		wg.Wait()
		synctest.Wait()
		if st.count() != 1 {
			t.Fatalf("reads=%d, want 1", st.count())
		}
		close(release)
		synctest.Wait()
		for range 100 {
			d.Lookup(t.Context(), node(1))
		}
		synctest.Wait()
		if st.count() != 1 {
			t.Fatalf("miss not remembered: reads=%d", st.count())
		}
		advance(2 * time.Second)
		d.Lookup(t.Context(), node(1))
		synctest.Wait()
		if st.count() != 2 {
			t.Fatalf("miss did not expire: reads=%d", st.count())
		}
	})
}
func TestDirectoryRefreshDropsRevoked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := &directoryStore{Store: NewMemoryStore()}
		entry := directoryDevice(t, st, 1, time.Now().Add(time.Hour), time.Now())
		directoryDevice(t, st, 2, time.Now().Add(time.Hour), time.Now())
		d := NewDirectory(st, DirectoryOptions{Clock: time.Now})
		directoryHit(t, d, node(1))
		directoryHit(t, d, node(2))
		takeChanged(t, d)
		stop := runDirectory(t, d)
		defer stop()
		requireNoError(t, st.DeleteDevice(t.Context(), entry.Ref))
		advance(10 * time.Second)
		synctest.Wait()
		got := d.Devices()
		if len(got) != 1 || got[0].NodeKey != node(2) {
			t.Fatalf("revoked device retained or sibling lost: %+v", got)
		}
		takeChanged(t, d)
		st.mu.Lock()
		lists := st.lists
		st.mu.Unlock()
		if lists != 1 {
			t.Fatalf("refresh reads=%d, want one batch for account", lists)
		}
	})
}
func TestDirectoryStoreDownKeepsUntilExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := &directoryStore{Store: NewMemoryStore()}
		directoryDevice(t, st, 1, time.Now().Add(30*time.Second), time.Now())
		d := NewDirectory(st, DirectoryOptions{Clock: time.Now})
		directoryHit(t, d, node(1))
		takeChanged(t, d)
		stop := runDirectory(t, d)
		defer stop()
		st.setDown()
		advance(10 * time.Second)
		synctest.Wait()
		if len(d.Devices()) != 1 {
			t.Fatal("outage removed live entry")
		}
		noChanged(t, d)
		d.Lookup(t.Context(), node(2))
		synctest.Wait()
		if len(d.Devices()) != 1 {
			t.Fatal("outage added an entry")
		}
		advance(20 * time.Second)
		synctest.Wait()
		if len(d.Devices()) != 0 {
			t.Fatal("expired entry survived outage")
		}
		takeChanged(t, d)
	})
}
func TestDirectoryBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := NewMemoryStore()
		for i := byte(1); i <= 3; i++ {
			directoryDevice(t, st, i, time.Now().Add(time.Hour), time.Now())
		}
		d := NewDirectory(st, DirectoryOptions{MaxEntries: 2, Clock: time.Now})
		directoryHit(t, d, node(1))
		directoryHit(t, d, node(2))
		directoryHit(t, d, node(1))
		directoryHit(t, d, node(3))
		got := d.Devices()
		if len(got) != 2 {
			t.Fatalf("bound: %d entries", len(got))
		}
		for _, p := range got {
			if p.NodeKey == node(2) {
				t.Fatal("LRU kept least recently used key")
			}
		}
	})
}
func TestDirectoryChangedEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := NewMemoryStore()
		entry := directoryDevice(t, st, 1, time.Now().Add(time.Hour), time.Now())
		h := addHost(t, st, 100, time.Now().Add(time.Hour), time.Now())
		d := NewDirectory(st, DirectoryOptions{Clock: time.Now})
		if cap(d.Changed()) != 1 {
			t.Fatalf("Changed cap=%d", cap(d.Changed()))
		}
		p := directoryHit(t, d, node(1))
		if string(p.Policy) != "direct_only" {
			t.Fatalf("Policy=%q", p.Policy)
		}
		takeChanged(t, d)
		hp := directoryHit(t, d, h.NodeKey)
		if !hp.IsHost || hp.Policy != nil {
			t.Fatalf("host policy: %+v", hp)
		}
		takeChanged(t, d)
		stop := runDirectory(t, d)
		defer stop()
		advance(10 * time.Second)
		synctest.Wait()
		noChanged(t, d)
		for _, change := range []string{"disco", "endpoints", "policy", "expiry"} {
			current, err := st.Device(t.Context(), entry.Ref, time.Now())
			requireNoError(t, err)
			r := *current.Registration
			switch change {
			case "disco":
				r.DiscoKey = disco(9)
			case "endpoints":
				r.Endpoints = []netip.AddrPort{endpoint(9)}
			case "policy":
				current.Policy = []byte("allow")
				_, err = st.PutDevice(t.Context(), current, 32, time.Now())
				requireNoError(t, err)
			case "expiry":
				current.LeaseExpires = current.LeaseExpires.Add(time.Hour)
				_, err = st.PutDevice(t.Context(), current, 32, time.Now())
				requireNoError(t, err)
				current.PresenceExpires = current.PresenceExpires.Add(time.Hour)
			}
			requireNoError(t, st.PutRegistration(t.Context(), entry.Ref, r, current.PresenceExpires, time.Now()))
			advance(10 * time.Second)
			synctest.Wait()
			select {
			case <-d.Changed():
			default:
				t.Errorf("%s: missing Changed event", change)
			}
			p = directoryHit(t, d, node(1))
			if p.DiscoKey != r.DiscoKey || p.Endpoints[0] != r.Endpoints[0] || string(p.Policy) != string(current.Policy) {
				t.Fatalf("%s not reflected: %+v", change, p)
			}
			if change == "expiry" && !p.Expires.Equal(current.LeaseExpires) {
				t.Fatalf("expiry=%v want %v", p.Expires, current.LeaseExpires)
			}
		}
		// Two unread events coalesce into one receive.
		d.Invalidate(node(1))
		directoryHit(t, d, node(1))
		takeChanged(t, d)
		noChanged(t, d)
		requireNoError(t, st.DeleteDevice(t.Context(), entry.Ref))
		advance(10 * time.Second)
		synctest.Wait()
		takeChanged(t, d)
		if len(d.Devices()) != 0 {
			t.Fatal("deleted entry visible")
		}
	})
}

func TestDirectoryInvalidationDuringRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		st := &directoryStore{Store: NewMemoryStore(), release: release}
		entry := directoryDevice(t, st, 1, time.Now().Add(time.Hour), time.Now())
		d := NewDirectory(st, DirectoryOptions{Clock: time.Now})
		d.Lookup(t.Context(), node(1))
		synctest.Wait()
		d.Invalidate(node(1))
		requireNoError(t, st.DeleteDevice(t.Context(), entry.Ref))
		close(release)
		synctest.Wait()
		if len(d.Devices()) != 0 {
			t.Fatal("invalidated read repopulated cache")
		}
		if _, err := st.Device(t.Context(), entry.Ref, time.Now()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("device still present: %v", err)
		}
	})
}
