// Package server provides coordination storage, enrollment and peer discovery.
package server

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/Silo-Server/shunpike/coordination/protocol"
)

// AccountID identifies the caller's account namespace.
type AccountID string

// DeviceID identifies one enrollment within an account.
type DeviceID string

// DeviceRef identifies an enrollment across accounts.
type DeviceRef struct {
	Account AccountID
	Device  DeviceID
}

// Principal is a credential verified by the caller, valid until Expires.
type Principal struct {
	Ref     DeviceRef
	NodeKey protocol.NodeKey
	Expires time.Time
}

// Device holds an enrollment lease and its independently expiring presence.
type Device struct {
	Ref             DeviceRef
	NodeKey         protocol.NodeKey
	Policy          []byte
	LeaseExpires    time.Time
	Registration    *protocol.Registration
	PresenceExpires time.Time
}

// HostEntry describes one host until PresenceExpires.
type HostEntry struct {
	Label           string
	NodeKey         protocol.NodeKey
	DiscoKey        protocol.DiscoKey
	Endpoints       []netip.AddrPort
	Origin          string
	PresenceExpires time.Time
}

// Store operations are atomic and return caller-owned values. Expiry at now is
// absent. Device leases and registration presence have independent deadlines.
type Store interface {
	// PutDevice enforces the live account cap and global node-key uniqueness.
	// A replacement changes the key index and clears registration atomically.
	PutDevice(ctx context.Context, d Device, maxPerAccount int, now time.Time) (replaced bool, err error)
	// Device returns ErrNotFound for a missing or expired lease.
	Device(ctx context.Context, ref DeviceRef, now time.Time) (Device, error)
	// DeviceByNodeKey resolves an unexpired lease or returns ErrNotFound.
	DeviceByNodeKey(ctx context.Context, k protocol.NodeKey, now time.Time) (Device, error)
	// ListDevices returns live leases sorted by Ref.Device, empty when none.
	ListDevices(ctx context.Context, account AccountID, now time.Time) ([]Device, error)
	// DeleteDevice removes only this member, its indices and confirmations.
	DeleteDevice(ctx context.Context, ref DeviceRef) error
	// PutRegistration requires a live lease with the same node key.
	PutRegistration(ctx context.Context, ref DeviceRef, reg protocol.Registration, presenceExpires, now time.Time) error
	// PutHost stores a host until its presence deadline.
	PutHost(ctx context.Context, h HostEntry, now time.Time) error
	// DeleteHost removes the host and its confirmations.
	DeleteHost(ctx context.Context, label string) error
	// Hosts returns live hosts sorted by label.
	Hosts(ctx context.Context, now time.Time) ([]HostEntry, error)
	// PutConfirmation stores a host's confirmation until expires; nil deletes it.
	PutConfirmation(ctx context.Context, hostLabel string, ref DeviceRef, c *protocol.Confirmation, expires, now time.Time) error
	// Confirmations returns live confirmations indexed by host label.
	Confirmations(ctx context.Context, ref DeviceRef, now time.Time) (map[string]protocol.Confirmation, error)
}

var (
	// ErrNotFound means the requested entry is absent or expired.
	ErrNotFound = errors.New("coordination entry not found")
	// ErrDeviceLimit means the account has reached its live enrollment cap.
	ErrDeviceLimit = errors.New("device limit reached")
	// ErrNodeKeyConflict means another live enrollment holds the node key.
	ErrNodeKeyConflict = errors.New("node key already enrolled")
	// ErrUnauthorized means the principal does not hold a live enrollment.
	ErrUnauthorized = errors.New("unauthorized principal")
	// ErrUnavailable means storage cannot currently evaluate the operation.
	ErrUnavailable = errors.New("coordination store unavailable")
)
