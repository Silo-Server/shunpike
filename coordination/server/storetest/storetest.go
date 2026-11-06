// Package storetest supplies a clock-independent Store conformance suite.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/darthShadow/shunpike/coordination/protocol"
	"github.com/darthShadow/shunpike/coordination/server"
)

// Run tests atomic storage semantics against a fresh store for each case.
// Every deadline is evaluated with an explicit now; no case waits on time.
func Run(t *testing.T, newStore func(t *testing.T) server.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := func(n byte) protocol.NodeKey { return protocol.NodeKey{n} }
	device := func(account, id string, n byte) server.Device {
		return server.Device{Ref: server.DeviceRef{Account: server.AccountID(account), Device: server.DeviceID(id)}, NodeKey: key(n), Policy: []byte("direct"), LeaseExpires: now.Add(time.Minute)}
	}
	put := func(t *testing.T, st server.Store, d server.Device, cap int, at time.Time) bool {
		t.Helper()
		replaced, err := st.PutDevice(ctx, d, cap, at)
		if err != nil {
			t.Fatalf("PutDevice: %v", err)
		}
		return replaced
	}
	reg := func(d server.Device) protocol.Registration {
		return protocol.Registration{NodeKey: d.NodeKey, DiscoKey: protocol.DiscoKey{1}, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1234")}}
	}
	t.Run("PutGetAndOwnership", func(t *testing.T) {
		st := newStore(t)
		d := device("a", "one", 1)
		if put(t, st, d, 32, now) {
			t.Fatal("new device reported replacement")
		}
		got, err := st.Device(ctx, d.Ref, now)
		if err != nil || !reflect.DeepEqual(got, d) {
			t.Fatalf("Device = %+v, %v; want %+v", got, err, d)
		}
		d.Policy[0] = 'x'
		got.Policy[0] = 'y'
		again, err := st.DeviceByNodeKey(ctx, d.NodeKey, now)
		if err != nil || string(again.Policy) != "direct" {
			t.Fatalf("stored policy aliases caller: %+v %v", again, err)
		}
	})
	t.Run("ExpiryBoundary", func(t *testing.T) {
		st := newStore(t)
		d := device("a", "one", 1)
		put(t, st, d, 32, now)
		for _, at := range []time.Time{d.LeaseExpires, d.LeaseExpires.Add(time.Second)} {
			if _, err := st.Device(ctx, d.Ref, at); !errors.Is(err, server.ErrNotFound) {
				t.Fatalf("expired Device: %v", err)
			}
			if _, err := st.DeviceByNodeKey(ctx, d.NodeKey, at); !errors.Is(err, server.ErrNotFound) {
				t.Fatalf("expired index: %v", err)
			}
		}
	})
	t.Run("ReplacementClearsRegistrationAndIndex", func(t *testing.T) {
		st := newStore(t)
		d := device("a", "one", 1)
		put(t, st, d, 1, now)
		r := reg(d)
		if err := st.PutRegistration(ctx, d.Ref, r, now.Add(time.Second), now); err != nil {
			t.Fatal(err)
		}
		d.NodeKey = key(2)
		if !put(t, st, d, 1, now) {
			t.Fatal("replacement not reported")
		}
		if _, err := st.DeviceByNodeKey(ctx, key(1), now); !errors.Is(err, server.ErrNotFound) {
			t.Fatalf("old index: %v", err)
		}
		got, err := st.DeviceByNodeKey(ctx, key(2), now)
		if err != nil || got.Registration != nil || !got.PresenceExpires.IsZero() {
			t.Fatalf("replacement: %+v %v", got, err)
		}
	})
	t.Run("ConflictAcrossAccounts", func(t *testing.T) {
		st := newStore(t)
		put(t, st, device("a", "one", 1), 32, now)
		if _, err := st.PutDevice(ctx, device("b", "two", 1), 32, now); !errors.Is(err, server.ErrNodeKeyConflict) {
			t.Fatalf("conflict: %v", err)
		}
	})
	t.Run("CapIgnoresLapsedLease", func(t *testing.T) {
		st := newStore(t)
		d := device("a", "one", 1)
		put(t, st, d, 1, now)
		next := device("a", "two", 2)
		next.LeaseExpires = d.LeaseExpires.Add(time.Minute)
		if _, err := st.PutDevice(ctx, next, 1, now); !errors.Is(err, server.ErrDeviceLimit) {
			t.Fatalf("cap: %v", err)
		}
		put(t, st, next, 1, d.LeaseExpires)
	})
	t.Run("RegistrationIdentityAndPresence", func(t *testing.T) {
		st := newStore(t)
		d := device("a", "one", 1)
		r := reg(d)
		if err := st.PutRegistration(ctx, d.Ref, r, now.Add(time.Second), now); !errors.Is(err, server.ErrNotFound) {
			t.Fatalf("missing lease: %v", err)
		}
		put(t, st, d, 32, now)
		wrong := r
		wrong.NodeKey = key(2)
		if err := st.PutRegistration(ctx, d.Ref, wrong, now.Add(time.Second), now); !errors.Is(err, server.ErrNotFound) {
			t.Fatalf("wrong key: %v", err)
		}
		expiry := now.Add(time.Second)
		if err := st.PutRegistration(ctx, d.Ref, r, expiry, now); err != nil {
			t.Fatal(err)
		}
		r.Endpoints[0] = netip.MustParseAddrPort("192.0.2.2:1234")
		live, err := st.Device(ctx, d.Ref, now)
		if err != nil || live.Registration == nil || live.Registration.Endpoints[0] == r.Endpoints[0] {
			t.Fatalf("registration ownership: %+v %v", live, err)
		}
		got, err := st.Device(ctx, d.Ref, expiry)
		if err != nil || got.Registration != nil {
			t.Fatalf("presence expiry must keep lease only: %+v %v", got, err)
		}
		if err := st.PutRegistration(ctx, d.Ref, r, expiry, d.LeaseExpires); !errors.Is(err, server.ErrNotFound) {
			t.Fatalf("expired lease registration: %v", err)
		}
	})
	t.Run("Hosts", func(t *testing.T) {
		st := newStore(t)
		h := server.HostEntry{Label: "host", NodeKey: key(8), DiscoKey: protocol.DiscoKey{8}, Endpoints: reg(device("a", "x", 8)).Endpoints, PresenceExpires: now.Add(time.Minute)}
		if err := st.PutHost(ctx, h, now); err != nil {
			t.Fatal(err)
		}
		got, err := st.Hosts(ctx, now)
		if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], h) {
			t.Fatalf("Hosts: %+v %v", got, err)
		}
		got[0].Endpoints[0] = netip.MustParseAddrPort("192.0.2.9:9")
		again, err := st.Hosts(ctx, now)
		if err != nil || again[0].Endpoints[0] != h.Endpoints[0] {
			t.Fatalf("host aliases caller: %+v %v", again, err)
		}
		got, err = st.Hosts(ctx, h.PresenceExpires)
		if err != nil || len(got) != 0 {
			t.Fatalf("expired host: %+v %v", got, err)
		}
		if err := st.PutHost(ctx, h, now); err != nil {
			t.Fatal(err)
		}
		if err := st.DeleteHost(ctx, h.Label); err != nil {
			t.Fatal(err)
		}
		got, err = st.Hosts(ctx, now)
		if err != nil || len(got) != 0 {
			t.Fatalf("deleted host: %+v %v", got, err)
		}
	})
	t.Run("Confirmations", func(t *testing.T) {
		st := newStore(t)
		d := device("a", "one", 1)
		put(t, st, d, 32, now)
		c := protocol.Confirmation{Peer: d.NodeKey, DiscoKey: protocol.DiscoKey{1}, Endpoint: netip.MustParseAddrPort("192.0.2.1:1")}
		expiry := now.Add(time.Second)
		if err := st.PutConfirmation(ctx, "host", d.Ref, &c, expiry, now); err != nil {
			t.Fatal(err)
		}
		got, err := st.Confirmations(ctx, d.Ref, now)
		if err != nil || got["host"] != c {
			t.Fatalf("Confirmations: %+v %v", got, err)
		}
		got["host"] = protocol.Confirmation{}
		got, err = st.Confirmations(ctx, d.Ref, now)
		if err != nil || got["host"] != c {
			t.Fatalf("confirmation aliases caller: %+v %v", got, err)
		}
		got, err = st.Confirmations(ctx, d.Ref, expiry)
		if err != nil || len(got) != 0 {
			t.Fatalf("expired confirmation: %+v %v", got, err)
		}
		if err := st.PutConfirmation(ctx, "host", d.Ref, &c, expiry, now); err != nil {
			t.Fatal(err)
		}
		if err := st.PutConfirmation(ctx, "host", d.Ref, nil, time.Time{}, now); err != nil {
			t.Fatal(err)
		}
		got, err = st.Confirmations(ctx, d.Ref, now)
		if err != nil || len(got) != 0 {
			t.Fatalf("nil deletion: %+v %v", got, err)
		}
		if err := st.PutConfirmation(ctx, "host", d.Ref, &c, expiry, now); err != nil {
			t.Fatal(err)
		}
		if err := st.DeleteDevice(ctx, d.Ref); err != nil {
			t.Fatal(err)
		}
		got, err = st.Confirmations(ctx, d.Ref, now)
		if err != nil || len(got) != 0 {
			t.Fatalf("deleted confirmations: %+v %v", got, err)
		}
	})
	t.Run("DeleteDeviceIndices", func(t *testing.T) {
		st := newStore(t)
		d := device("a", "one", 1)
		put(t, st, d, 1, now)
		if err := st.DeleteDevice(ctx, d.Ref); err != nil {
			t.Fatal(err)
		}
		if _, err := st.DeviceByNodeKey(ctx, d.NodeKey, now); !errors.Is(err, server.ErrNotFound) {
			t.Fatalf("deleted index: %v", err)
		}
		put(t, st, device("b", "two", 1), 1, now)
	})
	t.Run("ListDevicesSortedAndLive", func(t *testing.T) {
		st := newStore(t)
		b := device("a", "b", 1)
		a := device("a", "a", 2)
		expired := device("a", "expired", 3)
		expired.LeaseExpires = now
		for _, d := range []server.Device{b, a, expired, device("b", "other", 4)} {
			put(t, st, d, 32, now)
		}
		got, err := st.ListDevices(ctx, "a", now)
		if err != nil || len(got) != 2 || got[0].Ref != a.Ref || got[1].Ref != b.Ref {
			t.Fatalf("ListDevices: %+v %v", got, err)
		}
		got, err = st.ListDevices(ctx, "empty", now)
		if err != nil || len(got) != 0 {
			t.Fatalf("empty list: %+v %v", got, err)
		}
	})
	t.Run("WithdrawPreservesSiblingsAndCap", func(t *testing.T) {
		st := newStore(t)
		var devices []server.Device
		for i := range 32 {
			d := device("a", fmt.Sprintf("%02d", i), byte(i+1))
			put(t, st, d, 32, now)
			devices = append(devices, d)
		}
		if err := st.DeleteDevice(ctx, devices[0].Ref); err != nil {
			t.Fatal(err)
		}
		for _, d := range devices[1:] {
			if _, err := st.Device(ctx, d.Ref, now); err != nil {
				t.Fatalf("sibling lost: %v", err)
			}
		}
		listed, err := st.ListDevices(ctx, "a", now)
		if err != nil || len(listed) != 31 {
			t.Fatalf("siblings listed=%d err=%v", len(listed), err)
		}
		put(t, st, device("a", "first", 33), 32, now)
		if _, err := st.PutDevice(ctx, device("a", "second", 34), 32, now); !errors.Is(err, server.ErrDeviceLimit) {
			t.Fatalf("second new enrollment: %v", err)
		}
	})
	t.Run("ConcurrentAdmissionAtomic", func(t *testing.T) {
		st := newStore(t)
		results := make(chan error, 64)
		for i := range 64 {
			go func() { _, err := st.PutDevice(ctx, device("a", fmt.Sprint(i), byte(i+1)), 32, now); results <- err }()
		}
		successes := 0
		for range 64 {
			err := <-results
			if err == nil {
				successes++
			} else if !errors.Is(err, server.ErrDeviceLimit) {
				t.Fatal(err)
			}
		}
		if successes != 32 {
			t.Fatalf("admitted %d, want 32", successes)
		}
	})
}
