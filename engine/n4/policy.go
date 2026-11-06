// Package n4 serves HTTP/3 over an engine's admitted peer graph.
package n4

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go"
)

// LossProfile selects "both", "no_lower", "loss_thresh", or "off".
// Unknown profiles are refused by Policy.Validate.
type LossProfile string

// Policy selects QUIC loss handling and receive credit. A zero StreamWindow
// retains default credit; otherwise InitialStreamWindow is positive and no
// greater than StreamWindow. Connection credit is 1.5 times stream credit.
type Policy struct {
	Loss                              LossProfile
	InitialStreamWindow, StreamWindow uint64
	ACKDecimation                     bool
	ScaledGapLimit                    bool
}

// DefaultClientPolicy returns BBRv3 with both loss switches, ACK decimation,
// scaled gaps and stream credit growing from 4 MiB to 128 MiB.
func DefaultClientPolicy() Policy {
	return Policy{Loss: "both", InitialStreamWindow: 4 << 20, StreamWindow: 128 << 20, ACKDecimation: true, ScaledGapLimit: true}
}

// DefaultServerPolicy returns both loss switches and scaled gaps, default
// receive credit and no ACK decimation.
func DefaultServerPolicy() Policy { return Policy{Loss: "both", ScaledGapLimit: true} }

// Validate refuses unknown loss profiles, maximum credit outside 4-128 MiB
// (except zero), and initial credit inconsistent with the maximum.
func (p Policy) Validate() error {
	switch p.Loss {
	case "both", "no_lower", "loss_thresh", "off":
	default:
		return fmt.Errorf("unknown loss profile %q", p.Loss)
	}
	if p.StreamWindow != 0 && (p.StreamWindow < 4<<20 || p.StreamWindow > 128<<20) {
		return fmt.Errorf("stream window must be zero or 4-128 MiB")
	}
	if p.StreamWindow == 0 && p.InitialStreamWindow != 0 {
		return fmt.Errorf("initial window requires a maximum")
	}
	if p.StreamWindow != 0 && (p.InitialStreamWindow == 0 || p.InitialStreamWindow > p.StreamWindow) {
		return fmt.Errorf("initial window must be positive and at most the maximum")
	}
	return nil
}

// QUICConfig returns a fresh BBRv3 configuration. Call Validate before using
// caller-supplied policies; zero credit fields retain quic-go's defaults.
func (p Policy) QUICConfig() *quic.Config {
	c := &quic.Config{InitialPacketSize: 1200, HandshakeIdleTimeout: 20 * time.Second, MaxIdleTimeout: 10 * time.Second, KeepAlivePeriod: 3 * time.Second, CongestionControl: quic.CongestionControlBBRv3, PMTUBlackHoleDetection: true, ACKDecimation: p.ACKDecimation, ScaledStreamGapLimit: p.ScaledGapLimit}
	c.BBRNoLowerBounds = p.Loss == "both" || p.Loss == "no_lower"
	if p.Loss == "both" || p.Loss == "loss_thresh" {
		c.BBRLossThresholdPercent = 5
	}
	if p.StreamWindow != 0 {
		c.InitialStreamReceiveWindow = p.InitialStreamWindow
		c.MaxStreamReceiveWindow = p.StreamWindow
		c.InitialConnectionReceiveWindow = p.InitialStreamWindow * 3 / 2
		c.MaxConnectionReceiveWindow = p.StreamWindow * 3 / 2
	}
	return c
}
