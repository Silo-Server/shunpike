package protocol

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"slices"
)

// NetmapVersion returns raw base64url SHA-256 of canonical JSON with Version empty.
// Hosts, regions and endpoints are sorted on copies; m is never mutated.
func NetmapVersion(m Netmap) string {
	m.Version = ""
	m.Regions = slices.Clone(m.Regions)
	slices.SortFunc(m.Regions, func(a, b Region) int { return cmp.Compare(a.ID, b.ID) })
	m.Hosts = append([]Host{}, m.Hosts...)
	for i := range m.Hosts {
		m.Hosts[i].Endpoints = append([]netip.AddrPort{}, m.Hosts[i].Endpoints...)
		slices.SortFunc(m.Hosts[i].Endpoints, func(a, b netip.AddrPort) int { return a.Compare(b) })
	}
	slices.SortFunc(m.Hosts, func(a, b Host) int {
		if order := cmp.Compare(a.Label, b.Label); order != 0 {
			return order
		}
		return bytes.Compare(a.NodeKey[:], b.NodeKey[:])
	})
	encoded, err := json.Marshal(m)
	if err != nil {
		// All fields are concrete JSON-safe types with infallible text encoders.
		panic(err)
	}
	hash := sha256.Sum256(encoded)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
