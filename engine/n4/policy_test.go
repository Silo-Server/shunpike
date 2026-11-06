package n4

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func checkCommonPolicy(t *testing.T, c *quic.Config) {
	t.Helper()
	if c.CongestionControl != quic.CongestionControlBBRv3 || quic.CongestionControlName(c) != "bbr3" || !c.BBRNoLowerBounds || c.BBRLossThresholdPercent != 5 || !c.PMTUBlackHoleDetection || !c.ScaledStreamGapLimit || c.InitialPacketSize != 1200 || c.HandshakeIdleTimeout != 20*time.Second || c.MaxIdleTimeout != 10*time.Second || c.KeepAlivePeriod != 3*time.Second {
		t.Fatalf("unexpected policy: %+v", c)
	}
}

func TestClientPolicyMatchesMeasuredArm(t *testing.T) {
	c := DefaultClientPolicy().QUICConfig()
	checkCommonPolicy(t, c)
	if !c.ACKDecimation || c.InitialStreamReceiveWindow != 4194304 || c.MaxStreamReceiveWindow != 134217728 || c.InitialConnectionReceiveWindow != 6291456 || c.MaxConnectionReceiveWindow != 201326592 {
		t.Fatalf("client ACK/windows: %+v", c)
	}
}

func TestServerPolicy(t *testing.T) {
	c := DefaultServerPolicy().QUICConfig()
	checkCommonPolicy(t, c)
	if c.ACKDecimation || c.InitialStreamReceiveWindow != 0 || c.MaxStreamReceiveWindow != 0 || c.InitialConnectionReceiveWindow != 0 || c.MaxConnectionReceiveWindow != 0 {
		t.Fatalf("server ACK/windows: %+v", c)
	}
}

func TestLossProfiles(t *testing.T) {
	for _, row := range []struct {
		loss      LossProfile
		noLower   bool
		threshold uint8
	}{{"both", true, 5}, {"no_lower", true, 0}, {"loss_thresh", false, 5}, {"off", false, 0}} {
		t.Run(string(row.loss), func(t *testing.T) {
			p := DefaultServerPolicy()
			p.Loss = row.loss
			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}
			c := p.QUICConfig()
			if c.BBRNoLowerBounds != row.noLower || c.BBRLossThresholdPercent != row.threshold {
				t.Fatalf("loss fields = %v/%v, want %v/%v", c.BBRNoLowerBounds, c.BBRLossThresholdPercent, row.noLower, row.threshold)
			}
		})
	}
	p := DefaultServerPolicy()
	p.Loss = "unknown"
	if err := p.Validate(); err == nil {
		t.Fatal("unknown loss profile accepted")
	}
}

func TestPolicyValidate(t *testing.T) {
	for _, row := range []struct {
		name             string
		initial, maximum uint64
		valid            bool
	}{
		{"defaults", 0, 0, true},
		{"initial_without_maximum", 512 << 10, 0, false},
		{"below_minimum", 512 << 10, 3 << 20, false},
		{"minimum", 512 << 10, 4 << 20, true},
		{"maximum", 512 << 10, 128 << 20, true},
		{"above_maximum", 512 << 10, 129 << 20, false},
		{"missing_initial", 0, 128 << 20, false},
		{"initial_above_maximum", (128 << 20) + 1, 128 << 20, false},
		{"initial_equals_maximum", 128 << 20, 128 << 20, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			p := DefaultServerPolicy()
			p.InitialStreamWindow, p.StreamWindow = row.initial, row.maximum
			if err := p.Validate(); (err == nil) != row.valid {
				t.Fatalf("Validate() = %v, valid=%v", err, row.valid)
			}
		})
	}
}

func TestReceiveWindowsFromPolicy(t *testing.T) {
	for _, row := range []struct{ initial, maximum uint64 }{{4 << 20, 128 << 20}, {0, 0}} {
		p := DefaultServerPolicy()
		p.InitialStreamWindow, p.StreamWindow = row.initial, row.maximum
		c := p.QUICConfig()
		if c.InitialStreamReceiveWindow != row.initial || c.MaxStreamReceiveWindow != row.maximum || c.InitialConnectionReceiveWindow != row.initial*3/2 || c.MaxConnectionReceiveWindow != row.maximum*3/2 {
			t.Fatalf("windows for %d/%d: %+v", row.initial, row.maximum, c)
		}
	}
}
