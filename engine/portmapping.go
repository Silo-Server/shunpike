package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/portmapper"
	"tailscale.com/net/portmapper/portmappertype"
	"tailscale.com/util/eventbus"
)

var gatewayLookup = netmon.LikelyHomeRouterIP
var newPortMapper = portmapper.NewClient

// ProbePortMapping discovers UPnP, NAT-PMP, and PCP without creating a mapping.
// With no default gateway it returns NoGateway and sends nothing. It returns
// an error if the probe cannot run or ctx ends. A nil log discards diagnostics.
func ProbePortMapping(ctx context.Context, log *slog.Logger) (PortMappingReport, error) {
	netns.SetEnabled(false)
	if err := ctx.Err(); err != nil {
		return PortMappingReport{}, err
	}
	gateway, self, ok := gatewayLookup()
	if err := ctx.Err(); err != nil {
		return PortMappingReport{}, err
	}
	if !ok {
		return PortMappingReport{NoGateway: true}, nil
	}
	logf := probeLogf(ctx, log)
	bus := eventbus.NewWithOptions(eventbus.BusOptions{Logf: logf})
	defer bus.Close()
	client := newPortMapper(portmapper.Config{EventBus: bus, Logf: logf, NetMon: netmon.NewStatic()})
	defer func() {
		if err := client.Close(); err != nil {
			logf("close portmapper: %v", err)
		}
	}()
	// Freeze the exact lookup result so absence and probing use the same
	// gateway decision as portmapper's own default lookup.
	client.SetGatewayLookupFunc(func() (netip.Addr, netip.Addr, bool) { return gateway, self, true })
	result, err := client.Probe(ctx)
	if err != nil {
		logf("port mapping probe: %v", err)
	}
	return portMappingReport(result, err, ctx.Err())
}

func portMappingReport(result portmappertype.ProbeResult, err, ctxErr error) (PortMappingReport, error) {
	report := PortMappingReport{UPnP: result.UPnP, PMP: result.PMP, PCP: result.PCP}
	if ctxErr != nil {
		return report, ctxErr
	}
	if err != nil {
		// Probe reports listen errors before it can run, and read errors after
		// sending discovery packets. Preserve observations from the latter.
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Op != "read" {
			return report, fmt.Errorf("probe port mapping: %w", err)
		}
	}
	return report, nil
}
