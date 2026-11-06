package protocol

import (
	"fmt"
	"net/netip"
	"net/url"
)

// Validate returns ErrInvalid for a malformed registration; it never mutates r.
func (r Registration) Validate() error {
	if r.NodeKey.IsZero() || r.DiscoKey.IsZero() {
		return fmt.Errorf("%w: registration requires nonzero node and discovery keys", ErrInvalid)
	}
	if err := validateEndpoints(r.Endpoints); err != nil {
		return err
	}
	if len(r.Confirmations) > 64 {
		return fmt.Errorf("%w: more than 64 confirmations", ErrInvalid)
	}
	peers := make(map[NodeKey]bool, len(r.Confirmations))
	for _, c := range r.Confirmations {
		if err := c.Validate(); err != nil {
			return err
		}
		if c.Peer == r.NodeKey || peers[c.Peer] {
			return fmt.Errorf("%w: self or duplicate confirmation peer", ErrInvalid)
		}
		peers[c.Peer] = true
	}
	return nil
}

// Validate returns ErrInvalid for a malformed netmap; it never mutates m.
func (m Netmap) Validate() error {
	if m.LeaseSeconds < 10 || m.LeaseSeconds > 600 || m.RefreshSeconds < 1 || m.RefreshSeconds > m.LeaseSeconds/3 {
		return fmt.Errorf("%w: lease or refresh bounds", ErrInvalid)
	}
	if len(m.Hosts) > 256 {
		return fmt.Errorf("%w: more than 256 hosts", ErrInvalid)
	}
	regions := make(map[int]bool, len(m.Regions))
	for _, region := range m.Regions {
		parsed, err := url.Parse(region.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || regions[region.ID] {
			return fmt.Errorf("%w: region URL or duplicate ID", ErrInvalid)
		}
		regions[region.ID] = true
	}
	labels := make(map[string]bool, len(m.Hosts))
	keys := make(map[NodeKey]bool, len(m.Hosts))
	for _, host := range m.Hosts {
		if !validLabel(host.Label) || host.NodeKey.IsZero() || host.DiscoKey.IsZero() {
			return fmt.Errorf("%w: host label or identity", ErrInvalid)
		}
		if labels[host.Label] || keys[host.NodeKey] {
			return fmt.Errorf("%w: duplicate host label or node key", ErrInvalid)
		}
		labels[host.Label], keys[host.NodeKey] = true, true
		if (len(m.Regions) == 0 && host.HomeRegion != 0) || (len(m.Regions) > 0 && !regions[host.HomeRegion]) {
			return fmt.Errorf("%w: unknown home region", ErrInvalid)
		}
		if err := validateEndpoints(host.Endpoints); err != nil {
			return err
		}
		if host.Confirmation != nil {
			if err := host.Confirmation.Validate(); err != nil {
				return err
			}
			if host.Confirmation.Peer == host.NodeKey {
				return fmt.Errorf("%w: host confirms itself", ErrInvalid)
			}
		}
	}
	return nil
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 64 {
		return false
	}
	for i := range len(label) {
		c := label[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == ':' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func validateEndpoints(endpoints []netip.AddrPort) error {
	if len(endpoints) > 64 {
		return fmt.Errorf("%w: more than 64 endpoints", ErrInvalid)
	}
	for _, endpoint := range endpoints {
		if !validEndpoint(endpoint) {
			return fmt.Errorf("%w: invalid unicast endpoint", ErrInvalid)
		}
	}
	return nil
}

func validEndpoint(endpoint netip.AddrPort) bool {
	addr := endpoint.Addr().Unmap()
	return endpoint.IsValid() && endpoint.Port() != 0 && !addr.IsUnspecified() && !addr.IsMulticast()
}

// Validate returns an error wrapping ErrInvalid for zero peer or discovery keys
// or an invalid unicast endpoint. It never mutates c.
func (c Confirmation) Validate() error {
	if c.Peer.IsZero() || c.DiscoKey.IsZero() || !validEndpoint(c.Endpoint) {
		return fmt.Errorf("%w: confirmation identity or endpoint", ErrInvalid)
	}
	return nil
}
