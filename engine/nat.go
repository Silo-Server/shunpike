package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"

	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
)

// CheckNAT uses only the supplied host:port STUN servers. It returns an error
// for invalid server addresses, failure to start, or an ended context. Missing
// STUN responses leave false or unknown fields. A nil log discards diagnostics.
func CheckNAT(ctx context.Context, log *slog.Logger, stunServers []string) (NATReport, error) {
	netns.SetEnabled(false)
	if err := ctx.Err(); err != nil {
		return NATReport{}, err
	}
	dm, err := stunMap(stunServers)
	if err != nil {
		return NATReport{}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	mon := netmon.NewStatic()
	if mon.InterfaceState() == nil {
		return NATReport{}, errors.New("read network interface state for STUN")
	}
	client := &netcheck.Client{NetMon: mon, Logf: probeLogf(ctx, log)}
	if err := client.Standalone(ctx, ":0"); err != nil {
		return NATReport{}, fmt.Errorf("open STUN sockets: %w", err)
	}
	result, err := client.GetReport(ctx, dm, &netcheck.GetReportOpts{OnlySTUN: true})
	if err != nil {
		return NATReport{}, fmt.Errorf("probe STUN: %w", err)
	}
	report := NATReport{
		UDP:      result.UDP,
		IPv4:     result.IPv4,
		IPv6:     result.IPv6,
		GlobalV4: result.GlobalV4,
		GlobalV6: result.GlobalV6,
	}
	if varies, ok := result.MappingVariesByDestIP.Get(); ok {
		report.MappingVariesByDest = TriNo
		if varies {
			report.MappingVariesByDest = TriYes
		}
	}
	return report, ctx.Err()
}

func stunMap(servers []string) (*tailcfg.DERPMap, error) {
	if len(servers) == 0 {
		return nil, errors.New("STUN server list is empty")
	}
	dm := &tailcfg.DERPMap{Regions: make(map[tailcfg.DERPRegionID]*tailcfg.DERPRegion, len(servers))}
	for i, server := range servers {
		host, portText, err := net.SplitHostPort(server)
		if err != nil {
			return nil, fmt.Errorf("parse STUN server %q: %w", server, err)
		}
		port, err := strconv.Atoi(portText)
		if host == "" || err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid STUN server %q: require host and port 1-65535", server)
		}
		id := tailcfg.DERPRegionID(i + 1)
		name := "stun-" + strconv.Itoa(i+1)
		node := &tailcfg.DERPNode{Name: name, RegionID: id, HostName: host, STUNPort: port, STUNOnly: true}
		if ip, err := netip.ParseAddr(host); err == nil {
			node.IPv4, node.IPv6 = "none", "none"
			if ip.Is4() {
				node.IPv4 = ip.String()
			} else {
				node.IPv6 = ip.String()
			}
		}
		dm.Regions[id] = &tailcfg.DERPRegion{RegionID: id, RegionCode: name, Nodes: []*tailcfg.DERPNode{node}}
	}
	return dm, nil
}
