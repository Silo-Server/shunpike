package protocol

import (
	"bytes"
	"encoding/json"
)

// ConnectionWindowMillis is the length, in milliseconds, of the window in which
// CheckFrame counts a connection's bytes against BudgetLimits.ConnectionBytes.
const ConnectionWindowMillis = 90000

// BudgetLimits sets the numbers CheckFrame enforces. A field that is zero or
// negative uses its default, so the zero value selects every default.
type BudgetLimits struct {
	// PairFrameBurst is the pair frame bucket's capacity, in frames. Default 20.
	PairFrameBurst float64
	// PairFrameRate is the pair frame bucket's refill, in frames per second.
	// Default 5.
	PairFrameRate float64
	// PairByteBurst is the pair byte bucket's capacity, in bytes. It must be at
	// least the largest budgeted frame, 1,317 bytes (a 1,280-byte discovery body,
	// its 32-byte destination key and the 5-byte frame header), or that frame is
	// always refused. Default 25,600.
	PairByteBurst float64
	// PairByteRate is the pair byte bucket's refill, in bytes per second.
	// Default 6,400.
	PairByteRate float64
	// ConnectionBytes is the most bytes one connection may send in a 90-second
	// window, counting every observed frame including refused ones. Default
	// 1,048,576.
	ConnectionBytes int
}

// withDefaults returns l with each unset field replaced by its default.
func (l BudgetLimits) withDefaults() BudgetLimits {
	if l.PairFrameBurst <= 0 {
		l.PairFrameBurst = 20
	}
	if l.PairFrameRate <= 0 {
		l.PairFrameRate = 5
	}
	if l.PairByteBurst <= 0 {
		l.PairByteBurst = 25600
	}
	if l.PairByteRate <= 0 {
		l.PairByteRate = 6400
	}
	if l.ConnectionBytes <= 0 {
		l.ConnectionBytes = 1 << 20
	}
	return l
}

// Budget holds the pair token buckets and connection byte window for CheckFrame.
// Its zero value is ready for use; callers serialize access and supply milliseconds
// from one consistent clock. Retain connection state for one connection's lifetime
// and pair state for the normalized pair's lifetime, including both directions.
type Budget struct {
	// Limits sets the numbers for the frame being checked. CheckFrame reads it
	// from the Budget it receives, never from the storage Pair or Connection
	// selects, so every Budget passed for one traffic stream carries the same value.
	Limits BudgetLimits
	// Pair selects shared pair state, including across connections; nil uses b itself.
	// Only the pointed-to storage is used, not that value's own Pair selector.
	Pair *Budget
	// Connection selects shared connection state across pairs; nil uses b itself.
	// Only the pointed-to storage is used, not its own Connection selector.
	Connection *Budget
	// ConnectionLimit, when non-nil, returns a byte limit for the connection's
	// window that applies when it is above Limits.ConnectionBytes. CheckFrame
	// calls it only once the window's bytes pass Limits.ConnectionBytes, so a
	// limit that costs work to compute is not paid on every frame. Like Limits, it
	// is read from the Budget CheckFrame receives.
	ConnectionLimit       func() int
	frames, bytes         float64
	at                    int64
	overruns              int
	initialized           bool
	connectionBytes       int
	connectionAt          int64
	connectionInitialized bool
}

// Verdict is the envelope action and its reason; accept has an empty reason.
type Verdict struct {
	// Action is "accept", "drop" or "close".
	Action string
	// Reason names the rejected rule; it is empty on acceptance.
	Reason string
}

// CheckFrame checks a decoded client frame and updates b's traffic budgets.
// senderDisco is the authenticated sender's 32-byte key, first marks the initial
// frame, clientInfo is decrypted JSON, and pairLive states current authorization.
// b must be nonnil. nowMillis uses a consistent clock. Malformed frames close;
// unauthorized pairs and sender mismatches drop. It performs no I/O.
func CheckFrame(frameType byte, body []byte, senderDisco []byte, first bool, clientInfo string, pairLive bool, b *Budget, nowMillis int64) Verdict {
	limits := b.Limits.withDefaults()
	connection := b.Connection
	if connection == nil {
		connection = b
	}
	if !connection.connectionInitialized || nowMillis-connection.connectionAt >= ConnectionWindowMillis {
		connection.connectionInitialized = true
		connection.connectionAt = nowMillis
		connection.connectionBytes = 0
	}
	connection.connectionBytes += len(body) + 5
	if connection.connectionBytes > limits.ConnectionBytes && (b.ConnectionLimit == nil || connection.connectionBytes > b.ConnectionLimit()) {
		return Verdict{Action: "close", Reason: "connection_budget"}
	}
	if first || frameType == 2 {
		if !first || frameType != 2 || len(body) < 72 {
			return Verdict{Action: "close", Reason: "client_info"}
		}
		var fields struct {
			MeshKey string `json:"meshKey"`
		}
		if json.Unmarshal([]byte(clientInfo), &fields) != nil {
			return Verdict{Action: "close", Reason: "client_info"}
		}
		if fields.MeshKey != "" {
			return Verdict{Action: "close", Reason: "mesh"}
		}
		return Verdict{Action: "accept"}
	}
	switch frameType {
	case 4:
		if len(body) < 32 || len(body) > 32+1280 {
			return Verdict{Action: "close", Reason: "size"}
		}
		packet := body[32:]
		if len(packet) < 78 || !bytes.Equal(packet[:6], []byte{'T', 'S', 0xf0, 0x9f, 0x92, 0xac}) {
			return Verdict{Action: "close", Reason: "disco"}
		}
		if !pairLive {
			return Verdict{Action: "drop", Reason: "pair"}
		}
		if !bytes.Equal(packet[6:38], senderDisco) {
			return Verdict{Action: "drop", Reason: "sender"}
		}
	case 7:
		if len(body) != 1 || body[0] > 1 {
			return Verdict{Action: "close", Reason: "preferred"}
		}
	case 18, 19:
		if len(body) != 8 {
			return Verdict{Action: "close", Reason: "ping"}
		}
	default:
		return Verdict{Action: "close", Reason: "type"}
	}
	pair := b.Pair
	if pair == nil {
		pair = b
	}
	if !pair.initialized {
		pair.frames, pair.bytes, pair.at, pair.initialized = limits.PairFrameBurst, limits.PairByteBurst, nowMillis, true
	}
	elapsed := max(0, float64(nowMillis-pair.at)/1000)
	pair.frames = min(limits.PairFrameBurst, pair.frames+elapsed*limits.PairFrameRate)
	pair.bytes = min(limits.PairByteBurst, pair.bytes+elapsed*limits.PairByteRate)
	pair.at = nowMillis
	if pair.frames < 1 || pair.bytes < float64(len(body)+5) {
		pair.overruns++
		if pair.overruns >= 3 {
			return Verdict{Action: "close", Reason: "budget"}
		}
		return Verdict{Action: "drop", Reason: "budget"}
	}
	pair.frames--
	pair.bytes -= float64(len(body) + 5)
	pair.overruns = 0
	return Verdict{Action: "accept"}
}
