package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime"

	quic "github.com/quic-go/quic-go"
	"tailscale.com/net/netns"
)

var listenCapabilities = new(net.ListenConfig).ListenPacket

// ProbeCapabilities opens unconnected loopback UDP sockets, reads local socket
// facilities, and closes the sockets without sending packets. It returns an
// error if no probe can run or ctx ends. A nil log discards diagnostic messages.
func ProbeCapabilities(ctx context.Context, log *slog.Logger) (CapabilityReport, error) {
	netns.SetEnabled(false)
	if err := ctx.Err(); err != nil {
		return CapabilityReport{}, err
	}
	logf := probeLogf(ctx, log)
	v4, err := listenCapabilities(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		return CapabilityReport{}, fmt.Errorf("open capability IPv4 socket: %w", err)
	}
	defer closeProbeSocket(v4, logf)

	report := socketCapabilities(v4, "udp4", logf)
	report.Platform = runtime.GOOS
	// This explicit BBRv3 config reports the fork's sender selection without
	// opening a connection. A zero Config keeps the upstream sender.
	report.BBRSender = quic.CongestionControlName(&quic.Config{CongestionControl: quic.CongestionControlBBRv3})

	v6, err := listenCapabilities(ctx, "udp6", "[::1]:0")
	if err == nil {
		defer closeProbeSocket(v6, logf)
		other := socketCapabilities(v6, "udp6", logf)
		report.GSO = commonSupport(report.GSO, other.GSO)
		report.GRO = commonSupport(report.GRO, other.GRO)
		report.DF = commonSupport(report.DF, other.DF)
	} else {
		logf("capability IPv6 socket unavailable: %v", err)
	}
	return report, ctx.Err()
}

func commonSupport(a, b Support) Support {
	if a == Unsupported || b == Unsupported {
		return Unsupported
	}
	if a == SupportUnknown || b == SupportUnknown {
		return SupportUnknown
	}
	return Supported
}
