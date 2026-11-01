package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"tailscale.com/types/logger"
)

func probeLogf(ctx context.Context, log *slog.Logger) logger.Logf {
	if log == nil {
		return logger.Discard
	}
	return func(format string, args ...any) {
		log.DebugContext(ctx, fmt.Sprintf(format, args...))
	}
}

func closeProbeSocket(pc net.PacketConn, logf logger.Logf) {
	if err := pc.Close(); err != nil {
		logf("close capability socket: %v", err)
	}
}
