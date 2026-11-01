package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"tailscale.com/net/portmapper"
	"tailscale.com/net/portmapper/portmappertype"
)

func TestProbesCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	tests := []struct {
		name string
		run  func() error
	}{
		{"ProbeCapabilities", func() error { _, err := ProbeCapabilities(ctx, nil); return err }},
		{"CheckNAT", func() error { _, err := CheckNAT(ctx, nil, []string{"127.0.0.1:3478"}); return err }},
		{"ProbePortMapping", func() error { _, err := ProbePortMapping(ctx, nil); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v; want context.Canceled", err)
			}
		})
	}
}

func TestProbePortMappingNoGateway(t *testing.T) {
	oldLookup := gatewayLookup
	oldNew := newPortMapper
	newPortMapper = func(portmapper.Config) *portmapper.Client {
		t.Fatal("constructed a portmapper without a gateway; want no probe or packets")
		return nil
	}
	t.Cleanup(func() { newPortMapper = oldNew })
	gatewayLookup = func() (netip.Addr, netip.Addr, bool) { return netip.Addr{}, netip.Addr{}, false }
	t.Cleanup(func() { gatewayLookup = oldLookup })
	got, err := ProbePortMapping(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := (PortMappingReport{NoGateway: true}); got != want {
		t.Fatalf("report = %+v; want %+v", got, want)
	}
}

func TestSTUNServersInvalid(t *testing.T) {
	for _, servers := range [][]string{nil, {"missing-port"}, {":3478"}, {"stun.example:0"}, {"stun.example:65536"}, {"stun.example:stun"}} {
		if _, err := stunMap(servers); err == nil {
			t.Errorf("stunMap(%q) succeeded; want invalid server error", servers)
		}
	}
}

func TestPortMappingReportsPartialResults(t *testing.T) {
	failure := errors.New("socket IO failed")
	tests := []struct {
		name     string
		result   portmappertype.ProbeResult
		probeErr error
		ctxErr   error
		want     PortMappingReport
		wantErr  error
	}{
		{"partial read", portmappertype.ProbeResult{PMP: true}, &net.OpError{Op: "read", Err: failure}, nil, PortMappingReport{PMP: true}, nil},
		{"empty read", portmappertype.ProbeResult{}, &net.OpError{Op: "read", Err: failure}, nil, PortMappingReport{}, nil},
		{"cannot open", portmappertype.ProbeResult{}, &net.OpError{Op: "listen", Err: failure}, nil, PortMappingReport{}, failure},
		{"canceled read", portmappertype.ProbeResult{PCP: true}, &net.OpError{Op: "read", Err: failure}, context.Canceled, PortMappingReport{PCP: true}, context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := portMappingReport(tt.result, tt.probeErr, tt.ctxErr)
			if got != tt.want {
				t.Errorf("report = %+v; want %+v", got, tt.want)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v; want %v", err, tt.wantErr)
			}
		})
	}
}
