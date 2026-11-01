// Package engine provides local socket capabilities and explicit network probes.
// Every probe disables Tailscale network namespace binding for the process.
package engine

import "net/netip"

// SocketBufferBytes is magicsock's fixed socket buffer request in bytes.
const SocketBufferBytes = 7 << 20

// Support describes whether a socket facility is available.
type Support uint8

const (
	// SupportUnknown means the probe could not determine support.
	SupportUnknown Support = iota
	// Supported means the socket facility is available.
	Supported
	// Unsupported means the socket facility is unavailable.
	Unsupported
)

// BufferReport records a Linux socket buffer request and its outcome.
// Granted is the raw kernel readback, including Linux's doubling.
// Exactly one of Forced and a nonempty ForceErrno describes the FORCE attempt.
// All fields are zero on other platforms.
type BufferReport struct {
	Requested  int
	Granted    int
	Forced     bool
	ForceErrno string
}

// CapabilityReport describes local facilities without sending network traffic.
// Platform is runtime.GOOS.
// ReceiveBuffer and SendBuffer describe the IPv4 socket; feature support covers
// IPv4 and IPv6 when IPv6 is available. BBRSender names the default QUIC sender.
type CapabilityReport struct {
	Platform      string
	GSO           Support
	GRO           Support
	DF            Support
	ReceiveBuffer BufferReport
	SendBuffer    BufferReport
	BBRSender     string
}

// Tri is a result that distinguishes an unmeasured value from yes and no.
type Tri uint8

const (
	// TriUnknown means the probe could not determine a value.
	TriUnknown Tri = iota
	// TriYes means the observed value is true.
	TriYes
	// TriNo means the observed value is false.
	TriNo
)

// NATReport records STUN observations. Unobserved addresses are zero.
// MappingVariesByDest describes IPv4 mapping variation only.
type NATReport struct {
	UDP                 bool
	IPv4                bool
	IPv6                bool
	GlobalV4            netip.AddrPort
	GlobalV6            netip.AddrPort
	MappingVariesByDest Tri
}

// PortMappingReport records discovered router services without creating a mapping.
// NoGateway means the default gateway lookup failed and no probe packet was sent.
type PortMappingReport struct {
	UPnP      bool
	PMP       bool
	PCP       bool
	NoGateway bool
}
