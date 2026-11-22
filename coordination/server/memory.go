package server

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Silo-Server/shunpike/coordination/protocol"
)

type storedConfirmation struct {
	value   protocol.Confirmation
	expires time.Time
}
type memoryStore struct {
	mu            sync.Mutex
	devices       map[DeviceRef]Device
	byNode        map[protocol.NodeKey]DeviceRef
	accounts      map[AccountID]map[DeviceRef]struct{}
	hosts         map[string]HostEntry
	confirmations map[DeviceRef]map[string]storedConfirmation
}

// NewMemoryStore returns an empty concurrency-safe store with atomic indices.
// Stored slices and registrations never alias values supplied or returned.
func NewMemoryStore() Store {
	return &memoryStore{devices: make(map[DeviceRef]Device), byNode: make(map[protocol.NodeKey]DeviceRef), accounts: make(map[AccountID]map[DeviceRef]struct{}), hosts: make(map[string]HostEntry), confirmations: make(map[DeviceRef]map[string]storedConfirmation)}
}

func cloneRegistration(r protocol.Registration) protocol.Registration {
	r.Endpoints = slices.Clone(r.Endpoints)
	r.Confirmations = slices.Clone(r.Confirmations)
	return r
}
func cloneDevice(d Device, now time.Time) Device {
	d.Policy = slices.Clone(d.Policy)
	if d.Registration != nil && now.Before(d.PresenceExpires) {
		r := cloneRegistration(*d.Registration)
		d.Registration = &r
	} else {
		d.Registration = nil
	}
	return d
}
func cloneHost(h HostEntry) HostEntry { h.Endpoints = slices.Clone(h.Endpoints); return h }
func (m *memoryStore) deleteDevice(ref DeviceRef) {
	if d, ok := m.devices[ref]; ok {
		if m.byNode[d.NodeKey] == ref {
			delete(m.byNode, d.NodeKey)
		}
	}
	delete(m.devices, ref)
	delete(m.confirmations, ref)
	delete(m.accounts[ref.Account], ref)
	if len(m.accounts[ref.Account]) == 0 {
		delete(m.accounts, ref.Account)
	}
}
func (m *memoryStore) PutDevice(ctx context.Context, d Device, maxPerAccount int, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ref, ok := m.byNode[d.NodeKey]; ok && ref != d.Ref {
		if held, exists := m.devices[ref]; exists && now.Before(held.LeaseExpires) {
			return false, ErrNodeKeyConflict
		}
		m.deleteDevice(ref)
	}
	// The same account index drives both admission and enumeration.
	for ref := range m.accounts[d.Ref.Account] {
		if !now.Before(m.devices[ref].LeaseExpires) {
			m.deleteDevice(ref)
		}
	}
	old, exists := m.devices[d.Ref]
	if !exists && len(m.accounts[d.Ref.Account]) >= maxPerAccount {
		return false, ErrDeviceLimit
	}
	replaced := exists && old.NodeKey != d.NodeKey
	if replaced {
		m.deleteDevice(d.Ref)
	} else if exists {
		d.Registration = old.Registration
		d.PresenceExpires = old.PresenceExpires
	}
	d = cloneDevice(d, now)
	if m.accounts[d.Ref.Account] == nil {
		m.accounts[d.Ref.Account] = make(map[DeviceRef]struct{})
	}
	m.devices[d.Ref] = d
	m.byNode[d.NodeKey] = d.Ref
	m.accounts[d.Ref.Account][d.Ref] = struct{}{}
	return replaced, nil
}
func (m *memoryStore) Device(ctx context.Context, ref DeviceRef, now time.Time) (Device, error) {
	if err := ctx.Err(); err != nil {
		return Device{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[ref]
	if !ok || !now.Before(d.LeaseExpires) {
		return Device{}, ErrNotFound
	}
	return cloneDevice(d, now), nil
}
func (m *memoryStore) DeviceByNodeKey(ctx context.Context, k protocol.NodeKey, now time.Time) (Device, error) {
	if err := ctx.Err(); err != nil {
		return Device{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ref, ok := m.byNode[k]
	if !ok {
		return Device{}, ErrNotFound
	}
	d, ok := m.devices[ref]
	if !ok || !now.Before(d.LeaseExpires) {
		return Device{}, ErrNotFound
	}
	return cloneDevice(d, now), nil
}
func (m *memoryStore) ListDevices(ctx context.Context, account AccountID, now time.Time) ([]Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Device, 0, len(m.accounts[account]))
	for ref := range m.accounts[account] {
		d := m.devices[ref]
		if now.Before(d.LeaseExpires) {
			result = append(result, cloneDevice(d, now))
		}
	}
	slices.SortFunc(result, func(a, b Device) int { return strings.Compare(string(a.Ref.Device), string(b.Ref.Device)) })
	return result, nil
}
func (m *memoryStore) DeleteDevice(ctx context.Context, ref DeviceRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteDevice(ref)
	return nil
}
func (m *memoryStore) PutRegistration(ctx context.Context, ref DeviceRef, reg protocol.Registration, presenceExpires, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[ref]
	if !ok || !now.Before(d.LeaseExpires) || d.NodeKey != reg.NodeKey {
		return ErrNotFound
	}
	reg = cloneRegistration(reg)
	d.Registration = &reg
	d.PresenceExpires = presenceExpires
	m.devices[ref] = d
	return nil
}
func (m *memoryStore) PutHost(ctx context.Context, h HostEntry, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !now.Before(h.PresenceExpires) {
		delete(m.hosts, h.Label)
	} else {
		m.hosts[h.Label] = cloneHost(h)
	}
	return nil
}
func (m *memoryStore) DeleteHost(ctx context.Context, label string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.hosts, label)
	for _, cs := range m.confirmations {
		delete(cs, label)
	}
	return nil
}
func (m *memoryStore) Hosts(ctx context.Context, now time.Time) ([]HostEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]HostEntry, 0, len(m.hosts))
	for _, h := range m.hosts {
		if now.Before(h.PresenceExpires) {
			result = append(result, cloneHost(h))
		}
	}
	slices.SortFunc(result, func(a, b HostEntry) int { return strings.Compare(a.Label, b.Label) })
	return result, nil
}
func (m *memoryStore) PutConfirmation(ctx context.Context, label string, ref DeviceRef, c *protocol.Confirmation, expires, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if c == nil || !now.Before(expires) {
		delete(m.confirmations[ref], label)
		return nil
	}
	if m.confirmations[ref] == nil {
		m.confirmations[ref] = make(map[string]storedConfirmation)
	}
	m.confirmations[ref][label] = storedConfirmation{*c, expires}
	return nil
}
func (m *memoryStore) Confirmations(ctx context.Context, ref DeviceRef, now time.Time) (map[string]protocol.Confirmation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[string]protocol.Confirmation)
	for label, c := range m.confirmations[ref] {
		if now.Before(c.expires) {
			result[label] = c.value
		}
	}
	return result, nil
}
