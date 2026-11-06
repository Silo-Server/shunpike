package protocol

import (
	"bytes"
	"encoding/json"
)

// Budget holds the pair token buckets and connection byte window for CheckFrame.
// Its zero value is ready for use; callers serialize access and supply milliseconds
// from one consistent clock. Retain connection state for one connection's lifetime
// and pair state for the normalized pair's lifetime, including both directions.
type Budget struct {
	// Pair selects shared pair state, including across connections; nil uses b itself.
	// Only the pointed-to storage is used, not that value's own Pair selector.
	Pair *Budget
	// Connection selects shared connection state across pairs; nil uses b itself.
	// Only the pointed-to storage is used, not its own Connection selector.
	Connection            *Budget
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
	connection := b.Connection
	if connection == nil {
		connection = b
	}
	if !connection.connectionInitialized || nowMillis-connection.connectionAt >= 90000 {
		connection.connectionInitialized = true
		connection.connectionAt = nowMillis
		connection.connectionBytes = 0
	}
	connection.connectionBytes += len(body) + 5
	if connection.connectionBytes > 1<<20 {
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
		pair.frames, pair.bytes, pair.at, pair.initialized = 20, 25600, nowMillis, true
	}
	elapsed := max(0, float64(nowMillis-pair.at)/1000)
	pair.frames = min(20, pair.frames+elapsed*5)
	pair.bytes = min(25600, pair.bytes+elapsed*6400)
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
