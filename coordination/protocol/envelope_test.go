package protocol

import (
	"strings"
	"testing"
)

type envelopeVector struct {
	// Name identifies the frame case.
	Name string `json:"name"`
	// Type is the transport frame type.
	Type byte `json:"type"`
	// Body contains decoded frame bytes.
	Body []byte `json:"body"`
	// First marks the initial connection frame.
	First bool `json:"first"`
	// Info is authenticated, decrypted ClientInfo JSON.
	Info string `json:"info"`
	// PairLive supplies the current pair authorization.
	PairLive bool `json:"pairLive"`
	// Disco contains the sender's authenticated discovery key.
	Disco []byte `json:"disco"`
	// Repeat is the number of frames at one instant.
	Repeat int `json:"repeat"`
	// Want is the final action, optionally followed by a reason.
	Want string `json:"want"`
}

// TestEnvelopeVectors checks the shared frame decisions and overrun thresholds.
func TestEnvelopeVectors(t *testing.T) {
	for _, v := range readVectors[envelopeVector](t, "envelope") {
		t.Run(v.Name, func(t *testing.T) {
			var budget Budget
			var got Verdict
			for range v.Repeat {
				got = CheckFrame(v.Type, v.Body, v.Disco, v.First, v.Info, v.PairLive, &budget, 1000)
			}
			action, reason, _ := strings.Cut(v.Want, ":")
			if got != (Verdict{Action: action, Reason: reason}) {
				t.Fatalf("verdict = %+v, want %s", got, v.Want)
			}
		})
	}
}

// TestEnvelopeBudgetRefill checks burst exhaustion and continuous token refill.
func TestEnvelopeBudgetRefill(t *testing.T) {
	var budget Budget
	for range 20 {
		if got := CheckFrame(18, make([]byte, 8), nil, false, "", true, &budget, 1000); got.Action != "accept" {
			t.Fatalf("initial burst = %+v, want accept", got)
		}
	}
	if got := CheckFrame(18, make([]byte, 8), nil, false, "", true, &budget, 1000); got != (Verdict{Action: "drop", Reason: "budget"}) {
		t.Fatalf("exhausted bucket = %+v, want drop:budget", got)
	}
	if got := CheckFrame(18, make([]byte, 8), nil, false, "", true, &budget, 1200); got.Action != "accept" {
		t.Fatalf("refilled bucket = %+v, want accept", got)
	}
}

// TestEnvelopeConnectionBudget checks the connection cap and exact window reset.
func TestEnvelopeConnectionBudget(t *testing.T) {
	var budget Budget
	body := make([]byte, 72)
	for range (1 << 20) / (72 + 5) {
		if got := CheckFrame(2, body, nil, true, `{}`, true, &budget, 1000); got.Action != "accept" {
			t.Fatalf("within connection limit = %+v, want accept", got)
		}
	}
	if got := CheckFrame(2, body, nil, true, `{}`, true, &budget, 1000); got.Action != "close" {
		t.Fatalf("over connection limit = %+v, want close", got)
	}
	if got := CheckFrame(2, body, nil, true, `{}`, true, &budget, 91000); got.Action != "accept" {
		t.Fatalf("new connection window = %+v, want accept", got)
	}
}

// TestEnvelopeBudgetScopes checks independent sharing across pairs and connections.
func TestEnvelopeBudgetScopes(t *testing.T) {
	t.Run("pair-across-connections", func(t *testing.T) {
		var pair, connectionOne, connectionTwo Budget
		one := Budget{Pair: &pair, Connection: &connectionOne}
		two := Budget{Pair: &pair, Connection: &connectionTwo}
		for range 10 {
			for _, budget := range []*Budget{&one, &two} {
				if got := CheckFrame(18, make([]byte, 8), nil, false, "", true, budget, 1000); got.Action != "accept" {
					t.Fatalf("within shared pair burst = %+v, want accept", got)
				}
			}
		}
		if got := CheckFrame(18, make([]byte, 8), nil, false, "", true, &two, 1000); got != (Verdict{Action: "drop", Reason: "budget"}) {
			t.Fatalf("shared pair burst exhausted = %+v, want drop:budget", got)
		}
	})
	t.Run("connection-across-pairs", func(t *testing.T) {
		var pairOne, pairTwo, connection Budget
		one := Budget{Pair: &pairOne, Connection: &connection}
		two := Budget{Pair: &pairTwo, Connection: &connection}
		if got := CheckFrame(2, make([]byte, (1<<20)-5), nil, true, `{}`, true, &one, 1000); got.Action != "accept" {
			t.Fatalf("exact shared connection limit = %+v, want accept", got)
		}
		if got := CheckFrame(18, make([]byte, 8), nil, false, "", true, &two, 1000); got != (Verdict{Action: "close", Reason: "connection_budget"}) {
			t.Fatalf("shared connection limit exceeded = %+v, want close:connection_budget", got)
		}
		if got := CheckFrame(18, make([]byte, 8), nil, false, "", true, &two, 91000); got.Action != "accept" {
			t.Fatalf("shared connection window reset = %+v, want accept", got)
		}
	})
}

// TestEnvelopeConfiguredLimits checks that each configured number replaces its
// default and that unset numbers keep theirs.
func TestEnvelopeConfiguredLimits(t *testing.T) {
	ping := make([]byte, 8)
	for _, tc := range []struct {
		name   string
		limits BudgetLimits
		run    func(t *testing.T, b *Budget)
	}{
		{"frame burst and rate", BudgetLimits{PairFrameBurst: 3, PairFrameRate: 1}, func(t *testing.T, b *Budget) {
			for range 3 {
				if got := CheckFrame(18, ping, nil, false, "", true, b, 1000); got.Action != "accept" {
					t.Fatalf("within the configured burst = %+v, want accept", got)
				}
			}
			if got := CheckFrame(18, ping, nil, false, "", true, b, 1000); got != (Verdict{Action: "drop", Reason: "budget"}) {
				t.Fatalf("over the configured burst = %+v, want drop:budget", got)
			}
			if got := CheckFrame(18, ping, nil, false, "", true, b, 2000); got.Action != "accept" {
				t.Fatalf("one configured refill period later = %+v, want accept", got)
			}
		}},
		{"byte burst and rate", BudgetLimits{PairByteBurst: 26, PairByteRate: 13}, func(t *testing.T, b *Budget) {
			// A ping costs 13 bytes: two fit the burst, and one more fits per second.
			for range 2 {
				if got := CheckFrame(18, ping, nil, false, "", true, b, 1000); got.Action != "accept" {
					t.Fatalf("within the configured byte burst = %+v, want accept", got)
				}
			}
			if got := CheckFrame(18, ping, nil, false, "", true, b, 1000); got != (Verdict{Action: "drop", Reason: "budget"}) {
				t.Fatalf("over the configured byte burst = %+v, want drop:budget", got)
			}
			if got := CheckFrame(18, ping, nil, false, "", true, b, 2000); got.Action != "accept" {
				t.Fatalf("one configured byte refill period later = %+v, want accept", got)
			}
		}},
		{"connection bytes", BudgetLimits{ConnectionBytes: 80}, func(t *testing.T, b *Budget) {
			// A ClientInfo frame with a 72-byte body counts 77 bytes.
			body := make([]byte, 72)
			if got := CheckFrame(2, body, nil, true, `{}`, true, b, 1000); got.Action != "accept" {
				t.Fatalf("within the configured connection limit = %+v, want accept", got)
			}
			if got := CheckFrame(18, ping, nil, false, "", true, b, 1000); got != (Verdict{Action: "close", Reason: "connection_budget"}) {
				t.Fatalf("over the configured connection limit = %+v, want close:connection_budget", got)
			}
		}},
		{"unset fields keep their defaults", BudgetLimits{PairFrameBurst: 3}, func(t *testing.T, b *Budget) {
			// The byte bucket still holds 25,600 bytes and refills 6,400 per second.
			for range 3 {
				CheckFrame(18, ping, nil, false, "", true, b, 1000)
			}
			if got := CheckFrame(18, ping, nil, false, "", true, b, 1000); got.Action != "drop" {
				t.Fatalf("over the configured burst = %+v, want drop", got)
			}
			if got := CheckFrame(18, ping, nil, false, "", true, b, 1200); got.Action != "accept" {
				t.Fatalf("after the default refill (5 frames per s) = %+v, want accept", got)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, &Budget{Limits: tc.limits}) })
	}
}
