package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/darthShadow/shunpike/coordination/protocol"
)

// Options configures storage, regions and independent lease/presence deadlines.
// Zero durations select the documented defaults; Clock nil uses time.Now.
// Logger nil discards logs. MaxDevicesPerAccount zero selects 32.
// Hold must stay below protocol.NetmapRequestTimeout.
type Options struct {
	Store                Store
	Regions              []protocol.Region
	Clock                func() time.Time
	Logger               *slog.Logger
	MaxDevicesPerAccount int
	Presence             time.Duration
	Refresh              time.Duration
	Lease                time.Duration
	Hold                 time.Duration
	Reconcile            time.Duration
}

type netmapWaiters struct {
	changed chan struct{}
	readers int
}

// Server coordinates enrolled devices and live hosts over a shared Store.
// Run observes external host writes; Wake and WakeAll support external notices.
type Server struct {
	o              Options
	mu             sync.Mutex
	waiters        map[DeviceRef]*netmapWaiters
	confirmationMu sync.Mutex
}

// New validates options without reading the store. Missing storage, invalid
// durations, invalid regions and holds reaching the client timeout are refused.
func New(o Options) (*Server, error) {
	if o.Store == nil {
		return nil, fmt.Errorf("%w: missing store", protocol.ErrInvalid)
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.MaxDevicesPerAccount == 0 {
		o.MaxDevicesPerAccount = 32
	}
	if o.Presence == 0 {
		o.Presence = 90 * time.Second
	}
	if o.Refresh == 0 {
		o.Refresh = 30 * time.Second
	}
	if o.Lease == 0 {
		o.Lease = 90 * time.Second
	}
	if o.Hold == 0 {
		o.Hold = 25 * time.Second
	}
	if o.Reconcile == 0 {
		o.Reconcile = 5 * time.Second
	}
	if o.MaxDevicesPerAccount < 1 || o.Presence < 0 || o.Refresh < 0 || o.Lease < 0 || o.Hold < 0 || o.Hold >= protocol.NetmapRequestTimeout || o.Reconcile < 0 {
		return nil, fmt.Errorf("%w: coordination option bounds", protocol.ErrInvalid)
	}
	o.Regions = slices.Clone(o.Regions)
	if err := (protocol.Netmap{LeaseSeconds: int(o.Lease / time.Second), RefreshSeconds: int(o.Refresh / time.Second), Regions: o.Regions}).Validate(); err != nil {
		return nil, err
	}
	return &Server{o: o, waiters: make(map[DeviceRef]*netmapWaiters)}, nil
}

// Enroll atomically reserves a live device lease and opaque policy. It returns
// whether a live enrollment's node key was replaced, or a store admission error.
func (s *Server) Enroll(ctx context.Context, ref DeviceRef, k protocol.NodeKey, policy []byte, leaseExpires time.Time) (bool, error) {
	now := s.o.Clock()
	if ref.Account == "" || ref.Device == "" || k.IsZero() || !now.Before(leaseExpires) {
		return false, fmt.Errorf("%w: enrollment identity or deadline", protocol.ErrInvalid)
	}
	replaced, err := s.o.Store.PutDevice(ctx, Device{Ref: ref, NodeKey: k, Policy: policy, LeaseExpires: leaseExpires}, s.o.MaxDevicesPerAccount, now)
	if err != nil {
		return false, fmt.Errorf("enroll device: %w", err)
	}
	s.Wake(ref)
	return replaced, nil
}

// Withdraw deletes the enrollment and wakes its held netmaps. Callers separately
// disconnect region connections and remove the device from their engine.
func (s *Server) Withdraw(ctx context.Context, ref DeviceRef) error {
	if err := s.o.Store.DeleteDevice(ctx, ref); err != nil {
		return fmt.Errorf("withdraw device: %w", err)
	}
	s.Wake(ref)
	return nil
}

// Authorize requires a live credential and matching live enrollment. Missing
// enrollment returns ErrUnauthorized; storage outages remain storage errors.
func (s *Server) Authorize(ctx context.Context, p Principal) (Device, error) {
	now := s.o.Clock()
	if !now.Before(p.Expires) {
		return Device{}, ErrUnauthorized
	}
	d, err := s.o.Store.Device(ctx, p.Ref, now)
	if errors.Is(err, ErrNotFound) {
		return Device{}, ErrUnauthorized
	}
	if err != nil {
		return Device{}, fmt.Errorf("authorize device: %w", err)
	}
	if d.NodeKey != p.NodeKey || !now.Before(d.LeaseExpires) {
		return Device{}, ErrUnauthorized
	}
	return d, nil
}

// Register validates the body and principal identity, then stores independent
// presence for Presence. It never creates an enrollment and wakes this device.
func (s *Server) Register(ctx context.Context, p Principal, reg protocol.Registration) error {
	if err := reg.Validate(); err != nil {
		return err
	}
	if _, err := s.Authorize(ctx, p); err != nil {
		return err
	}
	if reg.NodeKey != p.NodeKey {
		return ErrUnauthorized
	}
	now := s.o.Clock()
	err := s.o.Store.PutRegistration(ctx, p.Ref, reg, now.Add(s.o.Presence), now)
	if errors.Is(err, ErrNotFound) {
		return ErrUnauthorized
	}
	if err != nil {
		return fmt.Errorf("register device: %w", err)
	}
	s.Wake(p.Ref)
	return nil
}

func (s *Server) watch(ref DeviceRef) (<-chan struct{}, func()) {
	s.mu.Lock()
	w := s.waiters[ref]
	if w == nil {
		w = &netmapWaiters{changed: make(chan struct{})}
		s.waiters[ref] = w
	}
	w.readers++
	ch := w.changed
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.readers--
		if w.readers == 0 {
			delete(s.waiters, ref)
		}
	}
}
func (s *Server) view(ctx context.Context, p Principal) (protocol.Netmap, error) {
	d, err := s.Authorize(ctx, p)
	if err != nil {
		return protocol.Netmap{}, err
	}
	now := s.o.Clock()
	hosts, err := s.o.Store.Hosts(ctx, now)
	if err != nil {
		return protocol.Netmap{}, fmt.Errorf("read hosts: %w", err)
	}
	cs, err := s.o.Store.Confirmations(ctx, p.Ref, now)
	if err != nil {
		return protocol.Netmap{}, fmt.Errorf("read confirmations: %w", err)
	}
	m := protocol.Netmap{LeaseSeconds: int(s.o.Lease / time.Second), RefreshSeconds: int(s.o.Refresh / time.Second), Regions: slices.Clone(s.o.Regions), Hosts: make([]protocol.Host, 0, len(hosts))}
	home := 0
	if len(m.Regions) > 0 {
		home = m.Regions[0].ID
	}
	for _, h := range hosts {
		ph := protocol.Host{Label: h.Label, NodeKey: h.NodeKey, DiscoKey: h.DiscoKey, Endpoints: slices.Clone(h.Endpoints), HomeRegion: home, Origin: h.Origin}
		if c, ok := cs[h.Label]; ok && d.Registration != nil && c.Peer == d.NodeKey && c.DiscoKey == d.Registration.DiscoKey {
			ph.Confirmation = &c
		}
		m.Hosts = append(m.Hosts, ph)
	}
	m.Version = protocol.NetmapVersion(m)
	return m, nil
}

// Netmap returns only live hosts, regions and timing hints. An empty or different
// version returns immediately. An equal version holds until a wake, Hold, or
// cancellation, then reauthorizes and reads the current view.
func (s *Server) Netmap(ctx context.Context, p Principal, sinceVersion string) (protocol.Netmap, error) {
	changed, unwatch := s.watch(p.Ref)
	defer unwatch()
	m, err := s.view(ctx, p)
	if err != nil {
		return protocol.Netmap{}, err
	}
	if sinceVersion == "" || m.Version != sinceVersion {
		return m, nil
	}
	timer := time.NewTimer(s.o.Hold)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return protocol.Netmap{}, ctx.Err()
	case <-changed:
	case <-timer.C:
	}
	return s.view(ctx, p)
}

// PutHost validates and renews a host's presence for Presence, then wakes all
// held netmaps. The caller publishes the host again on change and refresh.
func (s *Server) PutHost(ctx context.Context, h HostEntry) error {
	home := 0
	if len(s.o.Regions) > 0 {
		home = s.o.Regions[0].ID
	}
	m := protocol.Netmap{LeaseSeconds: int(s.o.Lease / time.Second), RefreshSeconds: int(s.o.Refresh / time.Second), Regions: s.o.Regions, Hosts: []protocol.Host{{Label: h.Label, NodeKey: h.NodeKey, DiscoKey: h.DiscoKey, Endpoints: h.Endpoints, HomeRegion: home, Origin: h.Origin}}}
	if err := m.Validate(); err != nil {
		return err
	}
	now := s.o.Clock()
	h.PresenceExpires = now.Add(s.o.Presence)
	if err := s.o.Store.PutHost(ctx, h, now); err != nil {
		return fmt.Errorf("put host: %w", err)
	}
	s.WakeAll()
	return nil
}

// DeleteHost removes a host and wakes all held netmaps after storage succeeds.
func (s *Server) DeleteHost(ctx context.Context, label string) error {
	if err := s.o.Store.DeleteHost(ctx, label); err != nil {
		return fmt.Errorf("delete host: %w", err)
	}
	s.WakeAll()
	return nil
}

// SetConfirmation stores a host's confirmation of c.Peer until now + Presence.
// Equal live identity renews its deadline without a wake or version change.
// Invalid c returns an error wrapping protocol.ErrInvalid before store access or wake.
func (s *Server) SetConfirmation(ctx context.Context, hostLabel string, c protocol.Confirmation) error {
	if err := c.Validate(); err != nil {
		return err
	}
	s.confirmationMu.Lock()
	defer s.confirmationMu.Unlock()
	now := s.o.Clock()
	d, err := s.o.Store.DeviceByNodeKey(ctx, c.Peer, now)
	if err != nil {
		return fmt.Errorf("confirmation device: %w", err)
	}
	cs, err := s.o.Store.Confirmations(ctx, d.Ref, now)
	if err != nil {
		return fmt.Errorf("read confirmation: %w", err)
	}
	old, exists := cs[hostLabel]
	if err := s.o.Store.PutConfirmation(ctx, hostLabel, d.Ref, &c, now.Add(s.o.Presence), now); err != nil {
		return fmt.Errorf("store confirmation: %w", err)
	}
	if !exists || old != c {
		s.Wake(d.Ref)
	}
	return nil
}

// ClearConfirmation removes this host's confirmation and wakes the device.
// A missing device returns ErrNotFound; no enrollment is recreated.
func (s *Server) ClearConfirmation(ctx context.Context, hostLabel string, device protocol.NodeKey) error {
	s.confirmationMu.Lock()
	defer s.confirmationMu.Unlock()
	now := s.o.Clock()
	d, err := s.o.Store.DeviceByNodeKey(ctx, device, now)
	if err != nil {
		return fmt.Errorf("confirmation device: %w", err)
	}
	if err := s.o.Store.PutConfirmation(ctx, hostLabel, d.Ref, nil, time.Time{}, now); err != nil {
		return fmt.Errorf("clear confirmation: %w", err)
	}
	s.Wake(d.Ref)
	return nil
}

// Wake releases all currently held netmaps for ref; it records no future event.
func (s *Server) Wake(ref DeviceRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w := s.waiters[ref]; w != nil {
		close(w.changed)
		w.changed = make(chan struct{})
	}
}

// WakeAll releases every currently held netmap, including external-store writes.
func (s *Server) WakeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range s.waiters {
		close(w.changed)
		w.changed = make(chan struct{})
	}
}

func (s *Server) hostVersion(ctx context.Context) (string, error) {
	hosts, err := s.o.Store.Hosts(ctx, s.o.Clock())
	if err != nil {
		return "", err
	}
	m := protocol.Netmap{}
	for _, h := range hosts {
		m.Hosts = append(m.Hosts, protocol.Host{Label: h.Label, NodeKey: h.NodeKey, DiscoKey: h.DiscoKey, Endpoints: h.Endpoints, Origin: h.Origin})
	}
	return protocol.NetmapVersion(m), nil
}

// Run rereads the host view every Reconcile and wakes held netmaps on changes.
// Store outages retain the last version for comparison. Cancellation returns nil.
func (s *Server) Run(ctx context.Context) error {
	version, err := s.hostVersion(ctx)
	if err != nil {
		s.o.Logger.WarnContext(ctx, "read host view", slog.Any("error", err))
	}
	ticker := time.NewTicker(s.o.Reconcile)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			next, err := s.hostVersion(ctx)
			if err != nil {
				s.o.Logger.WarnContext(ctx, "reconcile host view", slog.Any("error", err))
				continue
			}
			if next != version {
				version = next
				s.WakeAll()
			}
		}
	}
}
