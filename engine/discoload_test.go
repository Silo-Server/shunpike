//go:build discoload

package engine_test

// This file measures how much relay (DERP) signaling traffic one device and
// host pair sends, so that RegionOptions.Budget limits can be set from data.
// It runs the in-process lab with the region's caps off and records every
// client-to-region DERP frame. A device's frames are stamped where the region
// reads them, by wrapping the connection the region accepts, so bursts are
// measured as the region sees them (the socket may hold frames back under loss).
// The host's signaling connection is an in-process buffer, with no network
// between the host and the region, so its frames carry the send time. A second
// tap on each engine's own connection stamps frames before they are written;
// it feeds the cross-check against the engines' discovery log and the
// comparison with the arrival stamps. The traces replay through
// protocol.CheckFrame.
//
// The harness never compiles without -tags discoload. Network shaping (tc
// netem on loopback) and the never-direct firewall rule are applied outside the
// test, in the container that runs it. Inputs are test flags, given after
// -args:
//
//	-cell          label of the shaped cell, recorded with each run
//	-stun          "reachable" or "unreachable" STUN server
//	-driver        "ready" (Engine.Ready) or "passive" (poll Path only)
//	-devices       number of devices, each paired with the one host
//	-steady        time spent direct before the rebind
//	-media_mbit    media rate per device in Mbit/s; 0 sends no media
//	-never_direct  expect the pair to stay relayed (UDP blocked outside)
//	-runs          number of runs
//	-out           output folder; TestDiscoLoadRun and TestDiscoLoadBudget skip without it
//
// TestDiscoLoadRun writes trace.jsonl and run.json for each run.
// TestDiscoLoadBudget reads every run under -out and writes budget.json and
// budget.md.

import (
	"bufio"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"tailscale.com/net/stun"
	"tailscale.com/types/key"

	"github.com/Silo-Server/shunpike/coordination/protocol"
	"github.com/Silo-Server/shunpike/coordination/server"
	"github.com/Silo-Server/shunpike/engine"
	"github.com/Silo-Server/shunpike/engine/n4"
)

var (
	discoCell   = flag.String("cell", "0", "label of the shaped cell")
	discoSTUN   = flag.String("stun", "unreachable", "reachable or unreachable")
	discoDriver = flag.String("driver", "ready", "ready or passive")
	discoDevs   = flag.Int("devices", 1, "number of devices")
	discoSteady = flag.Duration("steady", 30*time.Second, "time spent direct before the rebind")
	discoMedia  = flag.Float64("media_mbit", 0, "media rate per device in Mbit/s; 0 sends no media")
	discoNever  = flag.Bool("never_direct", false, "expect each pair to stay relayed")
	discoRuns   = flag.Int("runs", 1, "number of runs")
	discoOut    = flag.String("out", "", "output folder")
)

const (
	// discoSTUNPort is the port of the reachable STUN server. It is fixed so that
	// the never-direct firewall rule can let STUN through.
	discoSTUNPort = 3478
	// discoSetupLimit bounds the wait for two-sided direct.
	discoSetupLimit = 60 * time.Second
	// discoNeverSetup is the setup time of a never-direct run, which has no
	// direct moment to wait for.
	discoNeverSetup = 10 * time.Second
	// discoRebindWindow is the time watched after Rebind.
	discoRebindWindow = 15 * time.Second
	// discoSettle is the time after two-sided direct before the steady window
	// starts: the direct trust lasts 6.5 s.
	discoSettle = 5 * time.Second
	// discoRateWindow is the window that sets the sustained rate.
	discoRateWindow = 10 * time.Second
	// discoMargin multiplies each observed p99 into a limit.
	discoMargin = 4
	// discoMinByteBurst is the smallest byte burst that admits the largest
	// budgeted frame.
	discoMinByteBurst = 1317
	// discoHostName names the host in traces.
	discoHostName = "host"
	// discoLagLimit is the longest a device frame may take from its write to the
	// region's read. A longer wait means the tap or the transport is broken.
	discoLagLimit = 10 * time.Second
)

// discoFrame is one client-to-region DERP frame.
type discoFrame struct {
	// TUS is the time since the run started, in microseconds: when the region
	// read the frame ("arrival", device frames) or when the engine began the write
	// that completed it ("send", host frames).
	TUS int64 `json:"t_us"`
	// SentUS is the time the engine began the write that completed the frame. It
	// equals TUS for a "send" frame.
	SentUS int64 `json:"sent_us"`
	// Stamp is "arrival" or "send": which tap set TUS.
	Stamp string `json:"stamp"`
	// Conn numbers the signaling connection the frame went through.
	Conn int `json:"conn"`
	// From names the sender: the host or a device.
	From string `json:"from"`
	// Pair names the device of the pair a SendPacket frame belongs to.
	Pair string `json:"pair,omitempty"`
	// Dir is "d2h" for a device frame and "h2d" for a host frame.
	Dir string `json:"dir"`
	// Type is the DERP frame type byte.
	Type byte `json:"type"`
	// Body is the frame body length in bytes.
	Body int `json:"body"`
	// Charged is the budget charge: the body length plus the 5-byte header.
	Charged int `json:"charged"`
	// Kind names the frame from its type and, for a SendPacket, its body length.
	Kind string `json:"kind"`
}

// discoKind names a frame. A SendPacket body is the 32-byte destination key
// plus the sealed discovery message, whose length identifies it: a ping is 156
// bytes, a pong 142 and a call-me-maybe 112+18N with N at least 1.
func discoKind(typ byte, body int) string {
	switch typ {
	case 2:
		return "client_info"
	case 7:
		return "preferred"
	case 18:
		return "derp_ping"
	case 19:
		return "derp_pong"
	case 4:
		switch {
		case body == 156:
			return "disco_ping"
		case body == 142:
			return "disco_pong"
		case body >= 130 && (body-112)%18 == 0:
			return "call_me_maybe"
		}
		return "disco_other"
	}
	return "other"
}

// discoRecorder collects the frames of every tapped connection in one run.
type discoRecorder struct {
	t0 time.Time
	// skip names a frame kind the send tap leaves out, skipArrival one the arrival
	// tap leaves out, and skew shifts every arrival stamp. They exist to show that
	// the cross-checks catch a tap that misses a kind or stamps wrongly.
	skip, skipArrival string
	skew              time.Duration

	mu      sync.Mutex
	names   map[protocol.NodeKey]string
	sent    []discoFrame // every frame an engine wrote, stamped before the write
	arrived []discoFrame // every device frame the region read, stamped after the read
	conns   int
	bad     int
}

func newDiscoRecorder(o discoOpts) *discoRecorder {
	return &discoRecorder{t0: time.Now(), skip: o.Skip, skipArrival: o.SkipArrival, skew: o.ArrivalSkew, names: map[protocol.NodeKey]string{}}
}

func (r *discoRecorder) name(k protocol.NodeKey, n string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names[k] = n
}

func (r *discoRecorder) now() int64 { return time.Since(r.t0).Microseconds() }

// discoStream parses the bytes of one connection as a DERP frame stream.
type discoStream struct {
	id      int
	from    string
	pending []byte
}

// open numbers a new connection of the named sender.
func (r *discoRecorder) open(from string) discoStream {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conns++
	return discoStream{id: r.conns, from: from}
}

// wrap returns c, an engine's own connection, behind the send tap.
func (r *discoRecorder) wrap(self protocol.NodeKey, c net.Conn) net.Conn {
	r.mu.Lock()
	from := r.names[self]
	r.mu.Unlock()
	return &tapConn{Conn: c, r: r, s: r.open(from)}
}

// accept returns c, a device connection the region accepted, behind the arrival
// tap.
func (r *discoRecorder) accept(p server.Principal, c net.Conn) net.Conn {
	r.mu.Lock()
	from := r.names[p.NodeKey]
	r.mu.Unlock()
	return &arrivalConn{Conn: c, r: r, s: r.open(from)}
}

// tapConn records a frame before the engine writes it, so a recorded frame is
// never missing from the send tap when the region has read it. A failed write
// leaves a recorded frame that never arrives. The mutex keeps the record order
// equal to the wire order.
type tapConn struct {
	net.Conn
	r   *discoRecorder
	wmu sync.Mutex
	s   discoStream
}

func (c *tapConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	at := c.r.now()
	c.r.mu.Lock()
	c.r.feed(&c.s, p, at, "send", c.r.skip, &c.r.sent)
	c.r.mu.Unlock()
	return c.Conn.Write(p)
}

// arrivalConn records a frame when the region's read of its last byte returns.
type arrivalConn struct {
	net.Conn
	r *discoRecorder
	s discoStream
}

func (c *arrivalConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		at := c.r.now() + c.r.skew.Microseconds()
		c.r.mu.Lock()
		c.r.feed(&c.s, p[:n], at, "arrival", c.r.skipArrival, &c.r.arrived)
		c.r.mu.Unlock()
	}
	return n, err
}

// feed appends bytes to the stream and records each frame they complete. The
// header is a type byte and a big-endian body length, as in region.go's reader.
// The caller holds r.mu.
func (r *discoRecorder) feed(s *discoStream, p []byte, at int64, stamp, skip string, into *[]discoFrame) {
	s.pending = append(s.pending, p...)
	for len(s.pending) >= 5 {
		size := int(binary.BigEndian.Uint32(s.pending[1:5]))
		if size > 256<<10 {
			r.bad++
			s.pending = nil
			return
		}
		if len(s.pending) < 5+size {
			return
		}
		typ, body := s.pending[0], s.pending[5:5+size]
		f := discoFrame{TUS: at, SentUS: at, Stamp: stamp, Conn: s.id, From: s.from, Type: typ, Body: size, Charged: size + 5, Kind: discoKind(typ, size)}
		f.Dir = "d2h"
		f.Pair = s.from
		if s.from == discoHostName {
			f.Dir = "h2d"
		}
		if typ == 4 && size >= 32 {
			var dst protocol.NodeKey
			copy(dst[:], body[:32])
			if s.from == discoHostName {
				f.Pair = r.names[dst]
			}
		} else {
			f.Pair = ""
		}
		if f.Kind != skip {
			*into = append(*into, f)
		}
		s.pending = s.pending[5+size:]
	}
}

// snapshot copies both lists under one lock.
func (r *discoRecorder) snapshot() (sent, arrived []discoFrame, bad int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.sent), slices.Clone(r.arrived), r.bad
}

// discoOpts selects one run.
type discoOpts struct {
	Cell      string
	STUN      string
	Driver    string
	Devices   int
	Steady    time.Duration
	Rebind    time.Duration
	MediaMbit float64
	Never     bool
	// Skip names a frame kind the send tap leaves out, SkipArrival one the arrival
	// tap leaves out, and ArrivalSkew shifts the arrival stamps (red checks only).
	Skip, SkipArrival string
	ArrivalSkew       time.Duration
}

// discoPair is the timeline of one device, in milliseconds since the run
// started. A value of -1 means the event did not happen.
type discoPair struct {
	Name      string         `json:"name"`
	StartMS   int64          `json:"start_ms"`
	DirectMS  int64          `json:"direct_ms"`
	SettleMS  int64          `json:"settle_ms"`
	RecoverMS int64          `json:"recover_ms"`
	Media     int64          `json:"media_bytes"`
	Classes   map[string]int `json:"path_classes"`
}

// discoRunInfo is run.json.
type discoRunInfo struct {
	Cell       string            `json:"cell"`
	STUN       string            `json:"stun"`
	Driver     string            `json:"driver"`
	Devices    int               `json:"devices"`
	Never      bool              `json:"never_direct"`
	MediaMbit  float64           `json:"media_mbit"`
	SteadyMS   int64             `json:"steady_ms"`
	RebindMS   int64             `json:"rebind_ms"`
	EndMS      int64             `json:"end_ms"`
	Pairs      []discoPair       `json:"pairs"`
	Drops      map[string]uint64 `json:"region_drops"`
	Closes     map[string]uint64 `json:"region_closes"`
	Suppressed map[string]int64  `json:"derp_data_suppressed"`
	Frames     int               `json:"frames"`
	BadFrames  int               `json:"bad_frames"`
	Kinds      map[string]int    `json:"kinds"`
	CrossCheck string            `json:"cross_check,omitempty"`
	// ArrivalCheck is the disagreement between the arrival tap and the send tap.
	ArrivalCheck string `json:"arrival_check,omitempty"`
	// ArrivalCounts holds, per kind, the device frames the region read and the
	// device frames the engines wrote.
	ArrivalCounts map[string][2]int `json:"arrival_counts_read_written"`
	// LagP99MS and LagMaxMS are the time from the write to the region's read of a
	// device frame.
	LagP99MS    float64           `json:"lag_p99_ms"`
	LagMaxMS    float64           `json:"lag_max_ms"`
	Errors      []string          `json:"errors,omitempty"`
	Gomaxprocs  int               `json:"gomaxprocs"`
	NumCPU      int               `json:"num_cpu"`
	CPUMS       int64             `json:"cpu_ms"`
	GoVersion   string            `json:"go_version"`
	DiscoCounts map[string][2]int `json:"disco_counts_tap_log"`
}

// discoLoadTLS returns a self-signed server configuration and the base64 SHA-256
// pin of its public key, which n4.Transport checks.
func discoLoadTLS(t *testing.T) (*tls.Config, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"peer.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}, base64.StdEncoding.EncodeToString(sum[:])
}

// discoServeSTUN answers STUN binding requests on a loopback UDP port until the
// test ends.
func discoServeSTUN(t *testing.T, port int) {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64<<10)
		for {
			n, src, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			if !stun.Is(buf[:n]) {
				continue
			}
			txid, err := stun.ParseBindingRequest(buf[:n])
			if err != nil {
				continue
			}
			_, _ = pc.WriteToUDPAddrPort(stun.Response(txid, src), src)
		}
	}()
	t.Cleanup(func() {
		_ = pc.Close()
		<-done
	})
}

// discoMediaHandler streams zero bytes at mbit Mbit/s until the request ends.
func discoMediaHandler(mbit float64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 32<<10)
		bytesPerSec := mbit * 1e6 / 8
		start := time.Now()
		var sent float64
		fl, _ := w.(http.Flusher)
		for r.Context().Err() == nil {
			if wait := time.Until(start.Add(time.Duration(sent / bytesPerSec * float64(time.Second)))); wait > 0 {
				time.Sleep(wait)
			}
			n, err := w.Write(chunk)
			if err != nil {
				return
			}
			sent += float64(n)
			if fl != nil {
				fl.Flush()
			}
		}
	})
}

// discoMediaLoop requests the media stream until ctx ends, counting the bytes
// read. A failed request is retried: a passive client sends its first request
// before any direct path exists.
func discoMediaLoop(ctx context.Context, c *http.Client, total *atomic.Int64) {
	buf := make([]byte, 64<<10)
	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://peer.invalid/media", nil)
		if err != nil {
			return
		}
		if resp, err := c.Do(req); err == nil {
			for {
				n, rerr := resp.Body.Read(buf)
				total.Add(int64(n))
				if rerr != nil {
					break
				}
			}
			_ = resp.Body.Close()
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// discoDevice is one device of a run.
type discoDevice struct {
	d     *device
	pair  discoPair
	media atomic.Int64
}

func discoBothDirect(host *host, dev *discoDevice) bool {
	return dev.d.e.Path(host.e.PublicKey()).Class == "direct" && host.e.Path(dev.d.e.PublicKey()).Class == "direct"
}

// discoWaitDirect polls both engines' Path every 50 ms until the pair is
// direct on both sides. It reports whether that happened within limit.
func discoWaitDirect(ctx context.Context, host *host, dev *discoDevice, limit time.Duration, classes map[string]int) bool {
	deadline := time.Now().Add(limit)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		class := string(dev.d.e.Path(host.e.PublicKey()).Class)
		classes[class]++
		if discoBothDirect(host, dev) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
		}
	}
}

// discoCountLines counts the engines' discovery log lines that went through
// DERP: pings and call-me-maybes the engine sent, pongs it received.
func discoCountLines(logs []*callMeMaybeLog) (ping, pong, cmm int) {
	for _, l := range logs {
		l.mu.Lock()
		for _, ln := range l.lines {
			m := ln.msg
			if !strings.Contains(m, "derp-") && !strings.Contains(m, "127.3.3.40:") {
				continue
			}
			switch {
			case strings.Contains(m, " sent ping "):
				ping++
			case strings.Contains(m, " sent call-me-maybe "):
				cmm++
			case strings.Contains(m, " got pong "):
				pong++
			}
		}
		l.mu.Unlock()
	}
	return ping, pong, cmm
}

// discoCrossCheck compares the tap's counts of discovery frames with the
// engines' own log. The caller snapshots the log first and the tap second, and a
// frame is logged only after it is written, so the log never holds more than the
// tap. A ping or call-me-maybe is logged by its sender right after the write, so
// the tap holds at most one more. A pong is logged only by its receiver, so the
// tap also holds the frames still in flight at the snapshot.
func discoCrossCheck(frames []discoFrame, logs []*callMeMaybeLog) (string, map[string][2]int) {
	ping, pong, cmm := discoCountLines(logs)
	var tp, tg, tc int
	for _, f := range frames {
		switch f.Kind {
		case "disco_ping":
			tp++
		case "disco_pong":
			tg++
		case "call_me_maybe":
			tc++
		}
	}
	counts := map[string][2]int{"disco_ping": {tp, ping}, "disco_pong": {tg, pong}, "call_me_maybe": {tc, cmm}}
	var bad []string
	for _, k := range []string{"disco_ping", "disco_pong", "call_me_maybe"} {
		slack := 1
		if k == "disco_pong" {
			slack = 2 + counts[k][0]/50
		}
		if tap, log := counts[k][0], counts[k][1]; log > tap || tap-log > slack {
			bad = append(bad, fmt.Sprintf("%s: tap %d, engine log %d", k, tap, log))
		}
	}
	if len(bad) > 0 {
		return strings.Join(bad, "; "), counts
	}
	return "", counts
}

// discoMerge builds a run's trace and checks the arrival tap against the send
// tap. A device's frames come from the arrival tap and the host's from the send
// tap. Each device writes its frames in order over a TCP stream, so its n-th
// arrived frame is its n-th written frame; the match must agree in type and
// size, the arrival must not come before the write, and the wait must stay under
// discoLagLimit. The snapshot holds both lists at once, a frame is recorded
// before its write, and the region reads only written frames, so no device has
// more arrived than written frames. The written frames still in flight at the
// snapshot are allowed as slack, as in discoCrossCheck.
func discoMerge(sent, arrived []discoFrame) (trace []discoFrame, problem string, counts map[string][2]int, lagP99, lagMax float64) {
	wrote, read := map[string][]discoFrame{}, map[string][]discoFrame{}
	counts = map[string][2]int{}
	for _, f := range sent {
		if f.From != discoHostName {
			wrote[f.From] = append(wrote[f.From], f)
			c := counts[f.Kind]
			c[1]++
			counts[f.Kind] = c
		}
	}
	for _, f := range arrived {
		read[f.From] = append(read[f.From], f)
		c := counts[f.Kind]
		c[0]++
		counts[f.Kind] = c
	}
	var bad []string
	for _, k := range slices.Sorted(maps.Keys(counts)) {
		if r, w := counts[k][0], counts[k][1]; r > w || w-r > 2+w/50 {
			bad = append(bad, fmt.Sprintf("%s: region read %d, engines wrote %d", k, r, w))
		}
	}
	var lags []float64
	for _, name := range slices.Sorted(maps.Keys(read)) {
		w := wrote[name]
		for i, a := range read[name] {
			var why string
			if i >= len(w) {
				why = "arrived and was never written"
			} else if s := w[i]; a.Type != s.Type || a.Body != s.Body {
				why = fmt.Sprintf("arrived as %s, was written as %s", a.Kind, s.Kind)
			} else if a.TUS < s.TUS {
				why = fmt.Sprintf("arrived %d us before it was written", s.TUS-a.TUS)
			} else if time.Duration(a.TUS-s.TUS)*time.Microsecond > discoLagLimit {
				why = fmt.Sprintf("arrived %d ms after it was written", (a.TUS-s.TUS)/1000)
			} else {
				a.SentUS = s.TUS
				lags = append(lags, float64(a.TUS-s.TUS)/1000)
				trace = append(trace, a)
				continue
			}
			bad = append(bad, fmt.Sprintf("%s frame %d (%s) %s", name, i, a.Kind, why))
			break
		}
	}
	for _, f := range sent {
		if f.From == discoHostName {
			trace = append(trace, f)
		}
	}
	slices.SortStableFunc(trace, func(a, b discoFrame) int { return cmp.Compare(a.TUS, b.TUS) })
	return trace, strings.Join(bad, "; "), counts, discoP99(lags), slices.Max(append(lags, 0))
}

// runDiscoLoad runs one measurement in the calling subtest and writes its
// trace and run.json under dir when dir is not empty. Problems with the run go
// into the returned Errors; only a setup failure stops the test.
func runDiscoLoad(t *testing.T, o discoOpts, dir string) (*discoRunInfo, []discoFrame) {
	t.Helper()
	if o.Never && o.Driver == "ready" {
		t.Fatal("never_direct needs the passive driver: Ready never returns")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	l := newLab(t, ctx, false)
	// Caps off: a refused frame closes a stream and changes engine behavior.
	l.budget = protocol.BudgetLimits{PairFrameBurst: 1e9, PairFrameRate: 1e9, PairByteBurst: 1e9, PairByteRate: 1e9, ConnectionBytes: 1e9}
	// Every device enrolls under one account; the server's default limit of 32
	// would refuse the 33rd. The host needs no entry of its own.
	l.maxDevices = o.Devices + 1
	l.reset()
	if o.STUN == "reachable" {
		discoServeSTUN(t, discoSTUNPort)
	}
	l.stun = fmt.Sprintf("127.0.0.1:%d", discoSTUNPort)
	rec := newDiscoRecorder(o)
	l.tap = rec.wrap
	l.accept = rec.accept
	var ru0 syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru0)
	since := func() int64 { return time.Since(rec.t0).Milliseconds() }
	info := &discoRunInfo{Cell: o.Cell, STUN: o.STUN, Driver: o.Driver, Devices: o.Devices, Never: o.Never, MediaMbit: o.MediaMbit, SteadyMS: o.Steady.Milliseconds(), Gomaxprocs: runtime.GOMAXPROCS(0), NumCPU: runtime.NumCPU(), GoVersion: runtime.Version()}

	hostPriv := engine.NodePrivateFromBytes(key.NewNode().Raw32())
	rec.name(hostPriv.Public(), discoHostName)
	h := l.startHost(t, hostPriv)
	var tlsClientPin string
	if o.MediaMbit > 0 {
		var serverTLS *tls.Config
		serverTLS, tlsClientPin = discoLoadTLS(t)
		srv := n4.NewServer(h.e, serverTLS, n4.DefaultServerPolicy(), discoMediaHandler(o.MediaMbit))
		go func() { _ = srv.Serve(h.e.PacketConn()) }()
		t.Cleanup(func() { _ = srv.Close() })
	}
	mediaCtx, stopMedia := context.WithCancel(ctx)
	var mediaWG sync.WaitGroup
	defer func() {
		stopMedia()
		mediaWG.Wait()
	}()
	startMedia := func(dev *discoDevice) {
		if o.MediaMbit <= 0 {
			return
		}
		tr := &n4.Transport{Engine: dev.d.e, Policy: n4.DefaultClientPolicy(), Resolve: func(host string) (protocol.NodeKey, string, bool) {
			return h.e.PublicKey(), tlsClientPin, host == "peer.invalid"
		}}
		t.Cleanup(func() { _ = tr.Close() })
		mediaWG.Add(1)
		go func() {
			defer mediaWG.Done()
			discoMediaLoop(mediaCtx, &http.Client{Transport: tr}, &dev.media)
		}()
	}

	devs := make([]*discoDevice, o.Devices)
	for i := range devs {
		name := fmt.Sprintf("d%02d", i)
		priv, cred := l.newCredential(t, name)
		rec.name(priv.Public(), name)
		dev := &discoDevice{d: l.startDevice(t, priv, cred), pair: discoPair{Name: name, StartMS: since(), DirectMS: -1, RecoverMS: -1, Classes: map[string]int{}}}
		devs[i] = dev
		if o.Driver == "passive" {
			startMedia(dev)
		}
	}

	// Setup: until two-sided direct, or the fixed time for a never-direct run.
	limit := discoSetupLimit
	if o.Never {
		limit = discoNeverSetup
	}
	var wg sync.WaitGroup
	for _, dev := range devs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if o.Driver == "ready" {
				rctx, stop := context.WithTimeout(ctx, limit)
				err := dev.d.e.Ready(rctx, h.e.PublicKey())
				stop()
				if err != nil {
					return
				}
			}
			if discoWaitDirect(ctx, h, dev, limit, dev.pair.Classes) {
				dev.pair.DirectMS = since()
			}
			if o.Driver == "ready" {
				startMedia(dev)
			}
		}()
	}
	wg.Wait()
	for _, dev := range devs {
		switch {
		case o.Never && dev.pair.DirectMS >= 0:
			info.Errors = append(info.Errors, dev.pair.Name+" went direct although UDP is blocked")
		case !o.Never && dev.pair.DirectMS < 0:
			info.Errors = append(info.Errors, dev.pair.Name+" did not reach two-sided direct")
		}
		dev.pair.SettleMS = dev.pair.DirectMS + discoSettle.Milliseconds()
		if dev.pair.DirectMS < 0 {
			dev.pair.SettleMS = discoNeverSetup.Milliseconds()
		}
	}

	// Steady window, then one rebind of every device, then the recovery window.
	select {
	case <-ctx.Done():
	case <-time.After(o.Steady):
	}
	info.RebindMS = since()
	for _, dev := range devs {
		dev.d.e.Rebind()
	}
	for _, dev := range devs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if discoWaitDirect(ctx, h, dev, o.Rebind, dev.pair.Classes) {
				dev.pair.RecoverMS = since()
			}
			rest := o.Rebind - time.Duration(since()-info.RebindMS)*time.Millisecond
			select {
			case <-ctx.Done():
			case <-time.After(rest):
			}
		}()
	}
	wg.Wait()
	info.EndMS = since()

	// Snapshot the engines' logs first and the taps second: a frame written in
	// between shows only in the taps, never the other way round.
	logs := []*callMeMaybeLog{h.cmm}
	for _, dev := range devs {
		logs = append(logs, dev.d.cmm)
	}
	var lines []*callMeMaybeLog
	for _, lg := range logs {
		lg.mu.Lock()
		c := &callMeMaybeLog{lines: slices.Clone(lg.lines)}
		lg.mu.Unlock()
		lines = append(lines, c)
	}
	sent, arrived, bad := rec.snapshot()
	frames, arrivalCheck, arrivalCounts, lagP99, lagMax := discoMerge(sent, arrived)
	st := l.cur.Load().region.Stats()
	info.Drops, info.Closes = st.Drops, st.Closes
	info.Suppressed = map[string]int64{discoHostName: h.e.DERPDataSuppressed()}
	var dsup int64
	for _, dev := range devs {
		dsup += dev.d.e.DERPDataSuppressed()
	}
	info.Suppressed["devices"] = dsup
	var ru1 syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru1)
	info.CPUMS = (ru1.Utime.Nano() + ru1.Stime.Nano() - ru0.Utime.Nano() - ru0.Stime.Nano()) / int64(time.Millisecond)
	stopMedia()
	for _, dev := range devs {
		dev.pair.Media = dev.media.Load()
		info.Pairs = append(info.Pairs, dev.pair)
		if o.Never && dev.pair.Media > 0 {
			info.Errors = append(info.Errors, fmt.Sprintf("%s received %d media bytes although UDP is blocked", dev.pair.Name, dev.pair.Media))
		}
	}
	info.Frames, info.BadFrames = len(frames), bad
	info.Kinds = map[string]int{}
	for _, f := range frames {
		info.Kinds[f.Kind]++
	}
	info.CrossCheck, info.DiscoCounts = discoCrossCheck(sent, lines)
	info.ArrivalCheck, info.ArrivalCounts, info.LagP99MS, info.LagMaxMS = arrivalCheck, arrivalCounts, lagP99, lagMax
	if bad > 0 {
		info.Errors = append(info.Errors, fmt.Sprintf("%d frame headers the tap could not parse", bad))
	}
	if n := info.Kinds["disco_other"] + info.Kinds["other"]; n > 0 {
		info.Errors = append(info.Errors, fmt.Sprintf("%d frames of an unclassified kind", n))
	}
	if len(info.Drops) > 0 || len(info.Closes) > 0 {
		info.Errors = append(info.Errors, fmt.Sprintf("region refused frames with the caps off: drops %v, closes %v", info.Drops, info.Closes))
	}
	if dir != "" {
		if err := discoWriteRun(dir, info, frames); err != nil {
			t.Fatal(err)
		}
	}
	return info, frames
}

func discoWriteRun(dir string, info *discoRunInfo, frames []discoFrame) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(dir, "trace.jsonl"))
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, fr := range frames {
		if err := enc.Encode(fr); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "run.json"), b, 0o644)
}

func discoOptsFromFlags(t *testing.T) discoOpts {
	t.Helper()
	if *discoSTUN != "reachable" && *discoSTUN != "unreachable" {
		t.Fatalf("-stun %q: want reachable or unreachable", *discoSTUN)
	}
	if *discoDriver != "ready" && *discoDriver != "passive" {
		t.Fatalf("-driver %q: want ready or passive", *discoDriver)
	}
	return discoOpts{Cell: *discoCell, STUN: *discoSTUN, Driver: *discoDriver, Devices: *discoDevs, Steady: *discoSteady, Rebind: discoRebindWindow, MediaMbit: *discoMedia, Never: *discoNever}
}

func discoArmName(o discoOpts) string {
	n := fmt.Sprintf("%s-%s-%s-d%d", o.Cell, o.Driver, o.STUN, o.Devices)
	if o.Never {
		n += "-never"
	}
	return n
}

// TestDiscoLoadRun makes -runs measurements of one arm and checks each one.
func TestDiscoLoadRun(t *testing.T) {
	if *discoOut == "" {
		t.Skip("-out is required")
	}
	o := discoOptsFromFlags(t)
	for i := range *discoRuns {
		t.Run(fmt.Sprintf("run%02d", i+1), func(t *testing.T) {
			info, _ := runDiscoLoad(t, o, filepath.Join(*discoOut, discoArmName(o), fmt.Sprintf("run%02d", i+1)))
			if info.CrossCheck != "" {
				t.Errorf("tap and engine log disagree: %s", info.CrossCheck)
			}
			if info.ArrivalCheck != "" {
				t.Errorf("arrival tap and send tap disagree: %s", info.ArrivalCheck)
			}
			for _, e := range info.Errors {
				t.Error(e)
			}
			classes, media, recovered, direct := map[string]int{}, int64(0), 0, int64(0)
			for _, p := range info.Pairs {
				for c, n := range p.Classes {
					classes[c] += n
				}
				media += p.Media
				direct = max(direct, p.DirectMS)
				if p.RecoverMS >= 0 {
					recovered++
				}
			}
			t.Logf("frames %d, kinds %v, cpu %d ms; %d pairs, direct at most %d ms, %d recovered after the rebind, path polls %v, media bytes %d; device frames wait %.1f ms (p99) %.1f ms (max) from write to the region's read", info.Frames, info.Kinds, info.CPUMS, len(info.Pairs), direct, recovered, classes, media, info.LagP99MS, info.LagMaxMS)
		})
	}
}

// discoQuick is the option set of the red checks: cell 0, unreachable STUN,
// the Ready driver and short windows.
func discoQuick(skip string) discoOpts {
	return discoOpts{Cell: "0", STUN: "unreachable", Driver: "ready", Devices: 1, Steady: 3 * time.Second, Rebind: 3 * time.Second, Skip: skip}
}

// TestDiscoLoadRedDefaultLimits replays a cell 0 trace at the protocol's default
// limits. The default limits drop frames, as the L8 flow does.
func TestDiscoLoadRedDefaultLimits(t *testing.T) {
	info, frames := runDiscoLoad(t, discoQuick(""), "")
	if len(info.Errors) > 0 || info.CrossCheck != "" || info.ArrivalCheck != "" {
		t.Fatalf("run problems: %v %s %s", info.Errors, info.CrossCheck, info.ArrivalCheck)
	}
	res := discoReplay(frames, protocol.BudgetLimits{})
	t.Logf("%d frames; at default limits: drops %v closes %v", len(frames), res.Drops, res.Closes)
	if res.Drops["budget"]+res.Closes["budget"] == 0 {
		t.Fatal("default limits refused no frame")
	}
	if off := discoReplay(frames, discoOff); off.refused() != 0 {
		t.Fatalf("replay with the caps off refused frames: %v %v", off.Drops, off.Closes)
	}
}

// TestDiscoLoadRedTapSkips runs the harness with a tap that leaves out one kind
// of discovery frame. The cross-check against the engine log must fail for each
// kind, and pass for the whole tap. A Ready-driven pair goes direct from the
// netmap endpoints and sends no call-me-maybe, so that kind comes from a passive
// run that sends media.
func TestDiscoLoadRedTapSkips(t *testing.T) {
	for _, skip := range []string{"", "disco_ping", "disco_pong", "call_me_maybe"} {
		t.Run("skip_"+skip, func(t *testing.T) {
			o := discoQuick(skip)
			if skip == "call_me_maybe" {
				o.Driver, o.MediaMbit = "passive", 20
			}
			info, _ := runDiscoLoad(t, o, "")
			t.Logf("counts (tap, log): %v; cross-check: %q", info.DiscoCounts, info.CrossCheck)
			if skip == "" && (info.CrossCheck != "" || info.ArrivalCheck != "") {
				t.Fatalf("the whole tap fails a cross-check: %s %s", info.CrossCheck, info.ArrivalCheck)
			}
			if skip == "" {
				return
			}
			if info.DiscoCounts[skip][1] == 0 {
				t.Fatalf("the engines sent no %s through DERP in this run, so the check shows nothing for it", skip)
			}
			if info.CrossCheck == "" {
				t.Fatalf("a tap that skips %s passes the cross-check", skip)
			}
		})
	}
}

// TestDiscoLoadRedArrivalTap runs the harness with an arrival tap that leaves
// out one kind or stamps every frame wrongly. The comparison with the send tap
// must fail for each, while the engine-log cross-check, which the send tap
// feeds, stays clean; the whole arrival tap passes both. It also shows that the
// trace holds arrival-stamped device frames.
func TestDiscoLoadRedArrivalTap(t *testing.T) {
	cases := []struct {
		name string
		set  func(*discoOpts)
	}{
		{"whole", func(*discoOpts) {}},
		{"skip_disco_ping", func(o *discoOpts) { o.SkipArrival = "disco_ping" }},
		{"skip_disco_pong", func(o *discoOpts) { o.SkipArrival = "disco_pong" }},
		{"stamps_one_second_early", func(o *discoOpts) { o.ArrivalSkew = -time.Second }},
		{"stamps_one_minute_late", func(o *discoOpts) { o.ArrivalSkew = time.Minute }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := discoQuick("")
			c.set(&o)
			info, frames := runDiscoLoad(t, o, "")
			t.Logf("counts (read, written): %v; lag p99 %.1f ms, max %.1f ms; check: %q", info.ArrivalCounts, info.LagP99MS, info.LagMaxMS, info.ArrivalCheck)
			if info.CrossCheck != "" {
				t.Fatalf("the send tap fails the engine-log cross-check: %s", info.CrossCheck)
			}
			if c.name != "whole" {
				if info.ArrivalCheck == "" {
					t.Fatalf("an arrival tap that %s passes the comparison with the send tap", c.name)
				}
				return
			}
			if info.ArrivalCheck != "" {
				t.Fatalf("the whole arrival tap fails the comparison: %s", info.ArrivalCheck)
			}
			var arrival, device int
			for _, f := range frames {
				if f.From != discoHostName {
					device++
					if f.Stamp == "arrival" && f.TUS >= f.SentUS {
						arrival++
					}
				}
			}
			if device == 0 || arrival != device {
				t.Fatalf("%d of %d device frames carry an arrival stamp at or after their write", arrival, device)
			}
			for _, k := range []string{"disco_ping", "disco_pong"} {
				if info.ArrivalCounts[k][0] == 0 {
					t.Fatalf("the region read no %s frame, so the comparison shows nothing for it", k)
				}
			}
		})
	}
}

// discoOff is a limit set far above any load.
var discoOff = protocol.BudgetLimits{PairFrameBurst: 1e12, PairFrameRate: 1e12, PairByteBurst: 1e12, PairByteRate: 1e12, ConnectionBytes: 1 << 60}

// discoResult counts the frames the envelope refuses in a replay.
type discoResult struct {
	Drops, Closes map[string]int
	Total         int
}

func (r discoResult) refused() int {
	n := 0
	for _, v := range r.Drops {
		n += v
	}
	for _, v := range r.Closes {
		n += v
	}
	return n
}

// discoBody builds a body of the recorded length that passes CheckFrame's shape
// checks: a SendPacket carries the discovery magic and the sender key (all
// zero here, as is the sender key passed in).
func discoBody(f discoFrame) []byte {
	b := make([]byte, f.Body)
	if f.Type == 4 && f.Body >= 32+6 {
		copy(b[32:], []byte{'T', 'S', 0xf0, 0x9f, 0x92, 0xac})
	}
	return b
}

// discoReplay feeds frames to protocol.CheckFrame the way region.go does: one
// Budget per connection, and one per pair for SendPacket frames. A close ends
// its connection; later frames of it are not replayed.
func discoReplay(frames []discoFrame, lim protocol.BudgetLimits) discoResult {
	frames = slices.Clone(frames)
	slices.SortStableFunc(frames, func(a, b discoFrame) int { return cmp.Compare(a.TUS, b.TUS) })
	conns := map[int]*protocol.Budget{}
	pairs := map[string]*protocol.Budget{}
	closed := map[int]bool{}
	res := discoResult{Drops: map[string]int{}, Closes: map[string]int{}}
	zero := make([]byte, 32)
	for _, f := range frames {
		if closed[f.Conn] {
			continue
		}
		cb := conns[f.Conn]
		if cb == nil {
			cb = &protocol.Budget{}
			conns[f.Conn] = cb
		}
		pb := cb
		if f.Type == 4 {
			if pb = pairs[f.Pair]; pb == nil {
				pb = &protocol.Budget{}
				pairs[f.Pair] = pb
			}
		}
		b := protocol.Budget{Limits: lim, Pair: pb, Connection: cb}
		res.Total++
		v := protocol.CheckFrame(f.Type, discoBody(f), zero, f.Type == 2, "{}", true, &b, f.TUS/1000)
		switch v.Action {
		case "drop":
			res.Drops[v.Reason]++
		case "close":
			res.Closes[v.Reason]++
			closed[f.Conn] = true
		}
	}
	return res
}

// discoMinBurst is the smallest bucket depth, in frames or in bytes, at which
// the frames pass the pair bucket at the given refill rate with no drop. Larger
// depth never drops more, so a binary search finds it. It uses CheckFrame
// itself with every other limit off.
func discoMinBurst(frames []discoFrame, rate float64, bytes bool) float64 {
	if len(frames) == 0 {
		return 0
	}
	hi := len(frames)
	if bytes {
		hi = 0
		for _, f := range frames {
			hi += f.Charged
		}
	}
	lim := discoOff
	if bytes {
		lim.PairByteRate = rate
	} else {
		lim.PairFrameRate = rate
	}
	lo := 1
	for lo < hi {
		mid := lo + (hi-lo)/2
		if bytes {
			lim.PairByteBurst = float64(mid)
		} else {
			lim.PairFrameBurst = float64(mid)
		}
		if discoReplay(frames, lim).refused() == 0 {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return float64(lo)
}

// discoPeakRate is the most frames, or charged bytes, any window of
// discoRateWindow holds among the frames at or after fromMS, per second.
func discoPeakRate(frames []discoFrame, fromMS int64, bytes bool) float64 {
	var ts []int64
	var w []int
	for _, f := range frames {
		if f.TUS/1000 >= fromMS {
			ts = append(ts, f.TUS/1000)
			w = append(w, 1)
			if bytes {
				w[len(w)-1] = f.Charged
			}
		}
	}
	span := discoRateWindow.Milliseconds()
	best, sum, lo := 0, 0, 0
	for hi := range ts {
		sum += w[hi]
		for ts[hi]-ts[lo] >= span {
			sum -= w[lo]
			lo++
		}
		best = max(best, sum)
	}
	return float64(best) / discoRateWindow.Seconds()
}

// discoConnWindowBytes is the most bytes one connection's frames charge inside
// one fixed 90-second window, restarted by the first frame after the previous
// window ends, as CheckFrame does.
func discoConnWindowBytes(frames []discoFrame) int {
	start, sum, best := int64(0), 0, 0
	for i, f := range frames {
		if i == 0 || f.TUS/1000-start >= 90000 {
			start, sum = f.TUS/1000, 0
		}
		sum += f.Charged
		best = max(best, sum)
	}
	return best
}

// discoP99 is the nearest-rank 99th percentile; with fewer than 100 samples it
// is the maximum.
func discoP99(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	return s[int(math.Ceil(0.99*float64(len(s))))-1]
}

// discoRun is a run read back from disk.
type discoRun struct {
	dir    string
	info   discoRunInfo
	frames []discoFrame
}

// discoRefusal says why a run cannot count toward the limits, or returns "". A
// run that recorded an error or a cross-check disagreement is not evidence of
// how a healthy pair behaves, so the budget refuses it.
func discoRefusal(r discoRun) string {
	var why []string
	if len(r.info.Errors) > 0 {
		why = append(why, "errors: "+strings.Join(r.info.Errors, "; "))
	}
	if r.info.CrossCheck != "" {
		why = append(why, "cross-check: "+r.info.CrossCheck)
	}
	if r.info.ArrivalCheck != "" {
		why = append(why, "arrival check: "+r.info.ArrivalCheck)
	}
	if r.info.BadFrames > 0 {
		why = append(why, fmt.Sprintf("%d unparsable frame headers", r.info.BadFrames))
	}
	return strings.Join(why, "; ")
}

func discoReadRuns(out string) ([]discoRun, error) {
	var runs []discoRun
	err := filepath.WalkDir(out, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "run.json" {
			return err
		}
		var r discoRun
		rel, err := filepath.Rel(out, filepath.Dir(p))
		if err != nil {
			return err
		}
		r.dir = rel
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &r.info); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		f, err := os.Open(filepath.Join(filepath.Dir(p), "trace.jsonl"))
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		dec := json.NewDecoder(bufio.NewReader(f))
		for {
			var fr discoFrame
			if err := dec.Decode(&fr); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("%s: %w", p, err)
			}
			r.frames = append(r.frames, fr)
		}
		runs = append(runs, r)
		return nil
	})
	return runs, err
}

// discoArm groups the runs of one cell, driver, STUN arm and device count.
type discoArm struct {
	Cell    string `json:"cell"`
	Driver  string `json:"driver"`
	STUN    string `json:"stun"`
	Devices int    `json:"devices"`
	Never   bool   `json:"never_direct"`
	Runs    int    `json:"runs"`
	Pairs   int    `json:"pairs"`
	// DirectMSMax is the slowest time to two-sided direct among the pairs.
	DirectMSMax int64 `json:"direct_ms_max"`
	// WindowP99 holds the p99 of each window's frame count per pair, keyed
	// "setup", "steady" and "rebind", each with "d2h", "h2d" and "sum".
	WindowP99 map[string]map[string]float64 `json:"window_frames_p99"`
	// P99 holds the raw p99 samples that become limits: "frame_rate",
	// "byte_rate" (per second, from the 10 s peak), "frame_burst", "byte_burst"
	// (the smallest zero-drop depth at the batch rate), and "conn_bytes_host",
	// "conn_bytes_device" (the largest 90 s window).
	P99 map[string]float64 `json:"p99"`
	// DefaultRefused counts frames the default limits refuse in a replay.
	DefaultRefused int `json:"default_limits_refused"`
	Frames         int `json:"frames"`
}

// discoBudget is budget.json.
type discoBudget struct {
	// Complete is false when the batch lacks a never-direct arm, so the rate is
	// the default and not a measurement.
	Complete bool `json:"complete"`
	// Refused lists the runs the budget did not read, each with its reason. A
	// batch with a refused run is not complete.
	Refused    []string              `json:"refused_runs,omitempty"`
	RateSource string                `json:"rate_source"`
	Margin     int                   `json:"margin"`
	Limits     protocol.BudgetLimits `json:"limits"`
	Arms       []discoArm            `json:"arms"`
}

type armKey struct {
	cell, driver, stun string
	devices            int
	never              bool
}

// discoWindows counts a pair's SendPacket frames in the setup, steady and
// rebind windows, per direction.
func discoWindows(r discoRun, p discoPair) map[string][2]int {
	out := map[string][2]int{}
	first := int64(-1)
	for _, f := range r.frames {
		if f.Type == 4 && f.Pair == p.Name {
			first = f.TUS / 1000
			break
		}
	}
	for _, f := range r.frames {
		if f.Type != 4 || f.Pair != p.Name {
			continue
		}
		ms := f.TUS / 1000
		w := ""
		switch {
		case ms >= r.info.RebindMS:
			w = "rebind"
		case ms >= p.SettleMS:
			w = "steady"
		case p.DirectMS < 0 || ms < p.DirectMS:
			w = "setup"
		}
		if w == "" || ms < first {
			continue
		}
		c := out[w]
		if f.Dir == "h2d" {
			c[1]++
		} else {
			c[0]++
		}
		out[w] = c
	}
	return out
}

func discoPairFrames(r discoRun, name string) []discoFrame {
	var out []discoFrame
	for _, f := range r.frames {
		if f.Type == 4 && f.Pair == name {
			out = append(out, f)
		}
	}
	return out
}

// discoConnFrames groups a run's frames by connection and reports whether the
// connection is the host's.
func discoConnFrames(r discoRun) (byConn map[int][]discoFrame, host map[int]bool) {
	byConn, host = map[int][]discoFrame{}, map[int]bool{}
	for _, f := range r.frames {
		byConn[f.Conn] = append(byConn[f.Conn], f)
		host[f.Conn] = f.From == discoHostName
	}
	return byConn, host
}

func discoBuild(runs []discoRun) discoBudget {
	groups := map[armKey][]discoRun{}
	var refused []string
	for _, r := range runs {
		if why := discoRefusal(r); why != "" {
			refused = append(refused, r.dir+": "+why)
			continue
		}
		k := armKey{r.info.Cell, r.info.Driver, r.info.STUN, r.info.Devices, r.info.Never}
		groups[k] = append(groups[k], r)
	}
	keys := make([]armKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b armKey) int {
		return cmp.Or(cmp.Compare(a.cell, b.cell), cmp.Compare(a.driver, b.driver), cmp.Compare(a.stun, b.stun), cmp.Compare(a.devices, b.devices), boolCmp(a.never, b.never))
	})
	// Pass 1: the rate, from the never-direct arms (R675).
	rate := protocol.BudgetLimits{PairFrameRate: 5, PairByteRate: 6400}
	b := discoBudget{Complete: false, Refused: refused, RateSource: "default", Margin: discoMargin}
	var rf, rb float64
	for _, k := range keys {
		if !k.never {
			continue
		}
		var fr, by []float64
		for _, r := range groups[k] {
			for _, p := range r.info.Pairs {
				fl := discoPairFrames(r, p.Name)
				fr = append(fr, discoPeakRate(fl, p.SettleMS, false))
				by = append(by, discoPeakRate(fl, p.SettleMS, true))
			}
		}
		rf, rb = max(rf, discoMargin*discoP99(fr)), max(rb, discoMargin*discoP99(by))
		b.Complete, b.RateSource = true, "never_direct_arm"
	}
	if b.Complete {
		rate.PairFrameRate, rate.PairByteRate = rf, rb
	}
	lim := protocol.BudgetLimits{PairFrameRate: rate.PairFrameRate, PairByteRate: rate.PairByteRate, PairByteBurst: discoMinByteBurst}
	// Pass 2: per arm samples, then each limit is the largest 4 x p99 over arms.
	for _, k := range keys {
		a := discoArm{Cell: k.cell, Driver: k.driver, STUN: k.stun, Devices: k.devices, Never: k.never, P99: map[string]float64{}, WindowP99: map[string]map[string]float64{}}
		win := map[string][3][]float64{}
		var fr, by, fb, bb, ch, cd []float64
		for _, r := range groups[k] {
			a.Runs++
			a.Frames += len(r.frames)
			a.DefaultRefused += discoReplay(r.frames, protocol.BudgetLimits{}).refused()
			for _, p := range r.info.Pairs {
				a.Pairs++
				a.DirectMSMax = max(a.DirectMSMax, p.DirectMS)
				pf := discoPairFrames(r, p.Name)
				fr = append(fr, discoPeakRate(pf, p.SettleMS, false))
				by = append(by, discoPeakRate(pf, p.SettleMS, true))
				fb = append(fb, discoMinBurst(pf, rate.PairFrameRate, false))
				bb = append(bb, discoMinBurst(pf, rate.PairByteRate, true))
				for name, c := range discoWindows(r, p) {
					w := win[name]
					w[0], w[1], w[2] = append(w[0], float64(c[0])), append(w[1], float64(c[1])), append(w[2], float64(c[0]+c[1]))
					win[name] = w
				}
			}
			byConn, host := discoConnFrames(r)
			for id, fl := range byConn {
				cw := float64(discoConnWindowBytes(fl))
				if host[id] {
					ch = append(ch, cw)
				} else {
					cd = append(cd, cw)
				}
				// Frames that are not SendPacket spend the connection's own bucket.
				var own []discoFrame
				for _, f := range fl {
					if f.Type == 7 || f.Type == 18 || f.Type == 19 {
						own = append(own, f)
					}
				}
				fb = append(fb, discoMinBurst(own, rate.PairFrameRate, false))
				bb = append(bb, discoMinBurst(own, rate.PairByteRate, true))
			}
		}
		for name, w := range win {
			a.WindowP99[name] = map[string]float64{"d2h": discoP99(w[0]), "h2d": discoP99(w[1]), "sum": discoP99(w[2])}
		}
		a.P99["frame_rate"], a.P99["byte_rate"] = discoP99(fr), discoP99(by)
		a.P99["frame_burst"], a.P99["byte_burst"] = discoP99(fb), discoP99(bb)
		a.P99["conn_bytes_host"], a.P99["conn_bytes_device"] = discoP99(ch), discoP99(cd)
		lim.PairFrameBurst = max(lim.PairFrameBurst, discoMargin*a.P99["frame_burst"])
		lim.PairByteBurst = max(lim.PairByteBurst, discoMargin*a.P99["byte_burst"])
		lim.ConnectionBytes = max(lim.ConnectionBytes, int(math.Ceil(discoMargin*max(a.P99["conn_bytes_host"], a.P99["conn_bytes_device"]))))
		b.Arms = append(b.Arms, a)
	}
	lim.PairFrameRate, lim.PairByteRate = math.Ceil(rate.PairFrameRate), math.Ceil(rate.PairByteRate)
	lim.PairFrameBurst, lim.PairByteBurst = math.Ceil(lim.PairFrameBurst), math.Ceil(lim.PairByteBurst)
	b.Limits = lim
	if len(refused) > 0 {
		b.Complete = false
	}
	return b
}

func boolCmp(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	}
	return 1
}

// discoMarkdown renders the per-arm table and the proposed limits.
func discoMarkdown(b discoBudget) string {
	var s strings.Builder
	s.WriteString("| cell | driver | stun | devices | never | runs | pairs | direct ms max | setup frames p99 | steady frames p99 | rebind frames p99 | frames/s p99 | frame burst p99 | bytes/s p99 | byte burst p99 | host conn bytes p99 | device conn bytes p99 | default-limit refusals |\n")
	s.WriteString("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, a := range b.Arms {
		fmt.Fprintf(&s, "| %s | %s | %s | %d | %v | %d | %d | %d | %.0f | %.0f | %.0f | %.1f | %.0f | %.0f | %.0f | %.0f | %.0f | %d |\n",
			a.Cell, a.Driver, a.STUN, a.Devices, a.Never, a.Runs, a.Pairs, a.DirectMSMax,
			a.WindowP99["setup"]["sum"], a.WindowP99["steady"]["sum"], a.WindowP99["rebind"]["sum"],
			a.P99["frame_rate"], a.P99["frame_burst"], a.P99["byte_rate"], a.P99["byte_burst"],
			a.P99["conn_bytes_host"], a.P99["conn_bytes_device"], a.DefaultRefused)
	}
	l := b.Limits
	for _, r := range b.Refused {
		fmt.Fprintf(&s, "\nREFUSED RUN %s\n", r)
	}
	fmt.Fprintf(&s, "\nProposed limits (%d x p99, largest over arms; rate source: %s; complete: %v):\n\n", b.Margin, b.RateSource, b.Complete)
	s.WriteString("| PairFrameBurst | PairFrameRate | PairByteBurst | PairByteRate | ConnectionBytes |\n|---|---|---|---|---|\n")
	fmt.Fprintf(&s, "| %.0f | %.0f | %.0f | %.0f | %d |\n", l.PairFrameBurst, l.PairFrameRate, l.PairByteBurst, l.PairByteRate, l.ConnectionBytes)
	return s.String()
}

// TestDiscoLoadBudget replays every run under -out through protocol.CheckFrame,
// writes budget.json and budget.md, and checks that the proposed limits refuse
// no frame of any run.
func TestDiscoLoadBudget(t *testing.T) {
	if *discoOut == "" {
		t.Skip("-out is required")
	}
	runs, err := discoReadRuns(*discoOut)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) == 0 {
		t.Fatalf("no run.json under %s", *discoOut)
	}
	b := discoBuild(runs)
	j, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	md := discoMarkdown(b)
	if err := os.WriteFile(filepath.Join(*discoOut, "budget.json"), j, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*discoOut, "budget.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%s", md)
	for _, r := range b.Refused {
		t.Errorf("refused run %s", r)
	}
	for _, r := range runs {
		if discoRefusal(r) != "" {
			continue
		}
		if res := discoReplay(r.frames, b.Limits); res.refused() != 0 {
			t.Errorf("%s %s %s run: the proposed limits refuse %v %v", r.info.Cell, r.info.Driver, r.info.STUN, res.Drops, res.Closes)
		}
	}
	if b.RateSource != "never_direct_arm" {
		t.Error("no never-direct arm in the batch: the rate is the default, not measured")
	}
}

// TestDiscoLoadBudgetRefusesFailedRuns checks that a run with a recorded error,
// a cross-check disagreement or an arrival-check disagreement does not count
// toward the limits and is listed, and that a clean run does count.
func TestDiscoLoadBudgetRefusesFailedRuns(t *testing.T) {
	frame := discoFrame{TUS: 1000, SentUS: 1000, Stamp: "arrival", Conn: 1, From: "d00", Pair: "d00", Dir: "d2h", Type: 4, Body: 156, Charged: 161, Kind: "disco_ping"}
	mk := func(dir string, edit func(*discoRunInfo)) discoRun {
		r := discoRun{dir: dir, frames: []discoFrame{frame}, info: discoRunInfo{Cell: "0", STUN: "unreachable", Driver: "ready", Devices: 1, Pairs: []discoPair{{Name: "d00"}}}}
		edit(&r.info)
		return r
	}
	runs := []discoRun{
		mk("clean", func(*discoRunInfo) {}),
		mk("errors", func(i *discoRunInfo) { i.Errors = []string{"d00 did not reach two-sided direct"} }),
		mk("cross", func(i *discoRunInfo) { i.CrossCheck = "disco_ping: tap 0, engine log 3" }),
		mk("arrival", func(i *discoRunInfo) { i.ArrivalCheck = "disco_ping: region read 0, engines wrote 3" }),
		mk("headers", func(i *discoRunInfo) { i.BadFrames = 1 }),
	}
	b := discoBuild(runs)
	if len(b.Refused) != 4 {
		t.Fatalf("refused %d runs, want 4: %v", len(b.Refused), b.Refused)
	}
	for i, want := range []string{"errors:", "cross:", "arrival:", "headers:"} {
		if !strings.HasPrefix(b.Refused[i], want) {
			t.Errorf("refused run %d is %q, want a prefix %q", i, b.Refused[i], want)
		}
	}
	if b.Complete {
		t.Error("a batch with refused runs is complete")
	}
	var frames int
	for _, a := range b.Arms {
		frames += a.Frames
	}
	if frames != 1 {
		t.Errorf("the arms read %d frames, want only the clean run's 1", frames)
	}
}

// TestDiscoLoadReplayMath checks the replay and the burst search on traces whose
// answer is known by hand.
func TestDiscoLoadReplayMath(t *testing.T) {
	ping := func(ms int64) discoFrame {
		return discoFrame{TUS: ms * 1000, Conn: 1, From: "d00", Pair: "d00", Dir: "d2h", Type: 4, Body: 156, Charged: 161, Kind: "disco_ping"}
	}
	var burst []discoFrame // 30 frames at one instant
	for range 30 {
		burst = append(burst, ping(0))
	}
	// At a refill of 1 frame/s, 30 simultaneous frames need a depth of 30.
	if got := discoMinBurst(burst, 1, false); got != 30 {
		t.Errorf("30 simultaneous frames: min burst %v, want 30", got)
	}
	// 10 frames, one every second, at 1 frame/s need a depth of 1... plus the
	// first: the bucket starts full, so depth 1 admits each frame as it refills.
	var even []discoFrame
	for i := range int64(10) {
		even = append(even, ping(i*1000))
	}
	if got := discoMinBurst(even, 1, false); got != 1 {
		t.Errorf("one frame per second at 1/s: min burst %v, want 1", got)
	}
	// Bytes: 30 frames of 161 bytes at once need 30 x 161.
	if got := discoMinBurst(burst, 1, true); got != 30*161 {
		t.Errorf("byte burst %v, want %d", got, 30*161)
	}
	// Default limits (20 frames, 5/s) refuse the burst: frames 21 and 22 drop,
	// and the third refusal in a row closes the stream.
	res := discoReplay(burst, protocol.BudgetLimits{})
	if res.Drops["budget"] != 2 || res.Closes["budget"] != 1 {
		t.Errorf("default limits: drops %v closes %v, want 2 budget drops and 1 close", res.Drops, res.Closes)
	}
	if got := discoPeakRate(burst, 0, false); got != 3 {
		t.Errorf("peak rate of 30 frames in one window: %v, want 3 per second", got)
	}
	if got, want := discoP99([]float64{1, 2, 3}), 3.0; got != want {
		t.Errorf("p99 of three samples: %v, want %v", got, want)
	}
}
