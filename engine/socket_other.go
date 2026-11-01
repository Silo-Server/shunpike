//go:build !linux

package engine

import (
	"net"

	"tailscale.com/types/logger"
)

func socketCapabilities(_ net.PacketConn, _ string, _ logger.Logf) CapabilityReport {
	return CapabilityReport{GSO: Unsupported, GRO: Unsupported, DF: Unsupported}
}
