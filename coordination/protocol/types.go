// Package protocol defines neutral coordination messages and their validation.
// It uses only the standard library and performs no network or environment reads.
package protocol

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// ErrTooLarge identifies a document exceeding its encoded byte limit.
var ErrTooLarge = errors.New("document too large")

// ErrInvalid identifies malformed JSON, keys or invalid coordination fields.
var ErrInvalid = errors.New("invalid coordination message")

// NetmapRequestTimeout bounds a client's netmap request; server holds stay below it.
const NetmapRequestTimeout = 35 * time.Second

// ProtocolRevision names the revision of the coordination contract. Its value is
// opaque: a consumer compares it for exact equality with a value it knows and
// reads no order or meaning into it. A change to the wire shapes, limits or
// decoder rules in this package, to signaling or discovery behavior, or to the
// N4 transport (QUIC v1, HTTP/3 with "h3", TLS 1.3 pinned by tls_pin), needs a
// new value.
const ProtocolRevision = "1"

// NodeKey is a public node identity. Its text is "nodekey:" and 64 lowercase hex digits.
// The zero value represents a missing identity and is invalid in messages.
type NodeKey [32]byte

// DiscoKey is a public discovery identity with text "discokey:" and 64 lowercase hex digits.
// The zero value represents a missing identity and is invalid in messages.
type DiscoKey [32]byte

// String returns the canonical text form of k, including a zero key.
func (k NodeKey) String() string { return "nodekey:" + hex.EncodeToString(k[:]) }

// MarshalText returns k's canonical text and a nil error.
func (k NodeKey) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText decodes a canonical node key. ErrInvalid leaves k unchanged.
func (k *NodeKey) UnmarshalText(text []byte) error { return decodeKey(k[:], text, "nodekey:") }

// IsZero reports whether k is the missing node identity.
func (k NodeKey) IsZero() bool { return k == NodeKey{} }

// String returns the canonical text form of k, including a zero key.
func (k DiscoKey) String() string { return "discokey:" + hex.EncodeToString(k[:]) }

// MarshalText returns k's canonical text and a nil error.
func (k DiscoKey) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText decodes a canonical discovery key. ErrInvalid leaves k unchanged.
func (k *DiscoKey) UnmarshalText(text []byte) error { return decodeKey(k[:], text, "discokey:") }

// IsZero reports whether k is the missing discovery identity.
func (k DiscoKey) IsZero() bool { return k == DiscoKey{} }

func decodeKey(dst, text []byte, prefix string) error {
	s := string(text)
	if !strings.HasPrefix(s, prefix) || len(s) != len(prefix)+64 {
		return fmt.Errorf("%w: key prefix or length", ErrInvalid)
	}
	if s != strings.ToLower(s) {
		return fmt.Errorf("%w: key must use lowercase hex", ErrInvalid)
	}
	decoded, err := hex.DecodeString(s[len(prefix):])
	if err != nil {
		return fmt.Errorf("%w: key encoding: %w", ErrInvalid, err)
	}
	copy(dst, decoded)
	return nil
}

// Confirmation binds an observed direct UDP pong to the peer's discovery identity.
type Confirmation struct {
	// Peer is the node whose direct pong was received.
	Peer NodeKey `json:"peer"`
	// DiscoKey is that node's discovery key at the pong.
	DiscoKey DiscoKey `json:"disco_key"`
	// Endpoint is the unicast UDP source of the pong, with a nonzero port.
	Endpoint netip.AddrPort `json:"endpoint"`
}

// Registration publishes one node's discovery identity, endpoints and confirmations.
// Validate checks nonzero keys, endpoint bounds and unique confirmation peers.
type Registration struct {
	// NodeKey identifies the registered node.
	NodeKey NodeKey `json:"node_key"`
	// DiscoKey identifies its discovery key.
	DiscoKey DiscoKey `json:"disco_key"`
	// Endpoints holds at most 64 unicast UDP endpoints.
	Endpoints []netip.AddrPort `json:"endpoints"`
	// Confirmations holds at most 64 distinct peer observations; absent means none.
	Confirmations []Confirmation `json:"confirmations,omitempty"`
}

// Region identifies a signaling operation served over HTTPS.
type Region struct {
	// ID is the identifier referenced by a host's HomeRegion.
	ID int `json:"id"`
	// Code is the region's short name.
	Code string `json:"code"`
	// URL is the absolute HTTPS URL of the signaling operation.
	URL string `json:"url"`
}

// Host publishes a host's identity and endpoints visible to the requesting device.
type Host struct {
	// Label is a unique 1-64 byte name using lowercase letters, digits or ._:-.
	Label string `json:"label"`
	// NodeKey is the host's unique, nonzero node identity.
	NodeKey NodeKey `json:"node_key"`
	// DiscoKey is the host's nonzero discovery identity.
	DiscoKey DiscoKey `json:"disco_key"`
	// Endpoints holds at most 64 unicast UDP endpoints.
	Endpoints []netip.AddrPort `json:"endpoints"`
	// HomeRegion selects a listed region, or 0 when Regions is empty.
	HomeRegion int `json:"home_region"`
	// Origin is opaque deployment data; absence means no origin is supplied.
	Origin string `json:"origin,omitempty"`
	// Confirmation is this host's observation of the requesting device, if any.
	Confirmation *Confirmation `json:"confirmation,omitempty"`
}

// Netmap grants a bounded lease on a device's visible hosts and signaling regions.
// Validate checks the wire invariants; the consumer checks its own identity.
type Netmap struct {
	// Version is the NetmapVersion hash of all other fields.
	Version string `json:"version"`
	// LeaseSeconds is in [10,600]; deployment default is 90.
	LeaseSeconds int `json:"lease_seconds"`
	// RefreshSeconds is in [1,LeaseSeconds/3]; deployment default is 30.
	RefreshSeconds int `json:"refresh_seconds"`
	// Regions is optional; none selects the client's BaseURL plus "/signal".
	Regions []Region `json:"regions,omitempty"`
	// Hosts holds at most 256 unique host identities.
	Hosts []Host `json:"hosts"`
}
