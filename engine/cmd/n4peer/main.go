// Command n4peer runs a server or a timed client over a static peer graph.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/darthShadow/shunpike/coordination/protocol"
	"github.com/darthShadow/shunpike/engine"
	"github.com/darthShadow/shunpike/engine/n4"
)

type identity struct {
	protocol.Registration
	Pin string `json:"pin"`
}

type options struct {
	role, mode, private, peerKey, peerDisco, endpoints, peerFile, readyFile, advertise, pin, pinFile, media, path, loss string
	port                                                                                                                uint
	gso                                                                                                                 bool
	window                                                                                                              uint64
	bytes, warmupBytes                                                                                                  int64
	duration, warmup, timeout, waitDirect                                                                               time.Duration
}

func main() {
	var o options
	flag.StringVar(&o.role, "role", "client", "server or client")
	flag.StringVar(&o.mode, "mode", "throughput", "throughput or range")
	flag.StringVar(&o.private, "private-key", "", "optional 32-byte private scalar as hex")
	flag.UintVar(&o.port, "udp-port", 0, "fixed UDP port; 0 selects an available port")
	flag.StringVar(&o.peerKey, "peer-key", "", "canonical peer node key")
	flag.StringVar(&o.peerDisco, "peer-disco-key", "", "canonical peer discovery key")
	flag.StringVar(&o.endpoints, "peer-endpoints", "", "comma-separated peer IP:port endpoints")
	flag.StringVar(&o.peerFile, "peer-file", "", "read the peer's ready JSON after publishing this peer's identity")
	flag.StringVar(&o.readyFile, "ready-file", "", "write this peer's identity JSON here before waiting for its peer")
	flag.StringVar(&o.advertise, "advertise", "", "advertised IP:port; default is loopback and the bound port")
	flag.StringVar(&o.pin, "pin", "", "trusted server SPKI SHA-256 pin in base64")
	flag.StringVar(&o.pinFile, "quic-pin-file", "", "server writes its public pin; client reads the trusted pin")
	flag.StringVar(&o.media, "media", "", "file served at /media with range support")
	flag.StringVar(&o.path, "path", "/media", "range request path")
	flag.StringVar(&o.loss, "loss", "both", "both, no_lower, loss_thresh, or off")
	flag.BoolVar(&o.gso, "gso", true, "send paced datagram trains together")
	flag.BoolVar(&o.gso, "direct-gso", true, "alias for --gso")
	flag.Uint64Var(&o.window, "window", 128<<20, "maximum client stream receive window in bytes")
	flag.Uint64Var(&o.window, "quic-max-stream-window", 128<<20, "alias for --window")
	flag.Int64Var(&o.bytes, "bytes", 512<<20, "payload bytes for an exact transfer")
	flag.Int64Var(&o.warmupBytes, "warmup-bytes", 8<<20, "unmeasured bytes before an exact transfer")
	flag.DurationVar(&o.duration, "duration", 0, "measurement duration after warm-up; 0 selects exact bytes")
	flag.DurationVar(&o.warmup, "warmup-duration", 5*time.Second, "unmeasured duration on the same connection")
	flag.DurationVar(&o.timeout, "timeout", 2*time.Minute, "total timeout for peer setup and transfer")
	flag.DurationVar(&o.waitDirect, "wait-direct", 0, "wait for an observed direct path; 0 disables")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, o); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, o options) error {
	if (o.role != "server" && o.role != "client") || (o.mode != "throughput" && o.mode != "range") || o.port > 65535 || o.timeout <= 0 || o.duration < 0 || o.warmup < 0 || o.waitDirect < 0 || o.bytes <= 0 || o.warmupBytes < 0 {
		return errors.New("invalid role, mode, port, duration or byte count")
	}
	p := n4.DefaultClientPolicy()
	if o.role == "server" {
		p = n4.DefaultServerPolicy()
	} else {
		p.StreamWindow = o.window
		if o.window == 0 {
			p.InitialStreamWindow = 0
		}
	}
	p.Loss = n4.LossProfile(o.loss)
	if err := p.Validate(); err != nil {
		return err
	}
	var scalar [32]byte
	if o.private == "" {
		if _, err := rand.Read(scalar[:]); err != nil {
			return err
		}
	} else {
		b, err := hex.DecodeString(o.private)
		if err != nil || len(b) != len(scalar) {
			return errors.New("private key must contain 32 hex-encoded bytes")
		}
		copy(scalar[:], b)
	}
	e, err := engine.New(ctx, engine.Config{PrivateKey: engine.NodePrivateFromBytes(scalar), Port: uint16(o.port), GSO: o.gso, StaticNetwork: true})
	if err != nil {
		return err
	}
	defer func() { _ = e.Close() }()
	var tc *tls.Config
	var pin string
	if o.role == "server" {
		tc, pin, err = serverIdentity()
		if err != nil {
			return err
		}
		if o.pinFile != "" {
			if err := os.WriteFile(o.pinFile, []byte(pin+"\n"), 0600); err != nil {
				return err
			}
		}
	}
	ep := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), e.LocalPort())
	if o.advertise != "" {
		ep, err = netip.ParseAddrPort(o.advertise)
		if err != nil {
			return err
		}
	}
	self := identity{Registration: protocol.Registration{NodeKey: e.PublicKey(), DiscoKey: e.DiscoKey(), Endpoints: []netip.AddrPort{ep}}, Pin: pin}
	encoded, err := json.Marshal(self)
	if err != nil {
		return err
	}
	if o.readyFile != "" {
		ready, err := os.CreateTemp(filepath.Dir(o.readyFile), ".peer-identity-")
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(ready.Name()) }()
		_, writeErr := ready.Write(append(encoded, '\n'))
		if err := errors.Join(writeErr, ready.Close()); err != nil {
			return err
		}
		if err := os.Rename(ready.Name(), o.readyFile); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, string(encoded))
	setup, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	peer, err := readPeer(setup, o)
	if err != nil {
		return err
	}
	if err := e.SetPeers([]engine.Peer{{NodeKey: peer.NodeKey, DiscoKey: peer.DiscoKey, Endpoints: peer.Endpoints, Expires: time.Now().Add(24 * time.Hour)}}); err != nil {
		return err
	}
	if o.role == "server" {
		h, err := handlers(o.media)
		if err != nil {
			return err
		}
		s := n4.NewServer(e, tc, p, h)
		done := context.AfterFunc(ctx, func() { _ = s.Close() })
		defer done()
		err = s.Serve(e.PacketConn())
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	if o.pin != "" {
		peer.Pin = o.pin
	}
	if o.pinFile != "" {
		b, err := os.ReadFile(o.pinFile)
		if err != nil {
			return err
		}
		peer.Pin = strings.TrimSpace(string(b))
	}
	if peer.Pin == "" {
		return errors.New("trusted peer pin required")
	}
	if o.waitDirect > 0 {
		wait, stop := context.WithTimeout(setup, o.waitDirect)
		defer stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for e.Path(peer.NodeKey).Class != "direct" {
			select {
			case <-wait.Done():
				return wait.Err()
			case <-tick.C:
			}
		}
	}
	tr := &n4.Transport{Engine: e, Policy: p, Resolve: func(host string) (protocol.NodeKey, string, bool) {
		return peer.NodeKey, peer.Pin, host == "peer.invalid"
	}}
	defer func() { _ = tr.Close() }()
	return transfer(setup, o, e, peer.NodeKey, tr)
}

func readPeer(ctx context.Context, o options) (identity, error) {
	var p identity
	if o.peerFile != "" {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			b, err := os.ReadFile(o.peerFile)
			if err == nil {
				if err := json.Unmarshal(b, &p); err != nil {
					return p, err
				}
				return p, p.Validate()
			}
			if !errors.Is(err, os.ErrNotExist) {
				return p, err
			}
			select {
			case <-ctx.Done():
				return p, ctx.Err()
			case <-tick.C:
			}
		}
	}
	if err := p.NodeKey.UnmarshalText([]byte(o.peerKey)); err != nil {
		return p, err
	}
	if err := p.DiscoKey.UnmarshalText([]byte(o.peerDisco)); err != nil {
		return p, err
	}
	for _, raw := range strings.Split(o.endpoints, ",") {
		ep, err := netip.ParseAddrPort(raw)
		if err != nil {
			return p, err
		}
		p.Endpoints = append(p.Endpoints, ep)
	}
	return p, p.Validate()
}

func serverIdentity() (*tls.Config, string, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"peer.invalid"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
	if err != nil {
		return nil, "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}, base64.StdEncoding.EncodeToString(sum[:]), nil
}

type randomContent struct {
	data         []byte
	size, offset int64
}

func (r *randomContent) Read(p []byte) (int, error) {
	if r.offset >= r.size {
		return 0, io.EOF
	}
	n := int(min(int64(len(p)), r.size-r.offset))
	for filled := 0; filled < n; {
		copied := copy(p[filled:n], r.data[r.offset%int64(len(r.data)):])
		filled += copied
		r.offset += int64(copied)
	}
	return n, nil
}

func (r *randomContent) Seek(offset int64, whence int) (int64, error) {
	var base int64
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		base = r.offset
	case io.SeekEnd:
		base = r.size
	default:
		return 0, errors.New("invalid seek origin")
	}
	if offset < -base || offset > r.size-base {
		return 0, errors.New("seek outside content")
	}
	r.offset = base + offset
	return r.offset, nil
}

func handlers(media string) (http.Handler, error) {
	payload := make([]byte, 64<<10)
	if _, err := rand.Read(payload); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /random", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if err != nil || n < 0 {
			http.Error(w, "bytes must be a nonnegative int64", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		http.ServeContent(w, r, "random", time.Time{}, &randomContent{data: payload, size: n})
	})
	mux.HandleFunc("GET /media", func(w http.ResponseWriter, r *http.Request) {
		if media == "" {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(media)
		if err != nil {
			http.Error(w, "media unavailable", http.StatusNotFound)
			return
		}
		defer func() { _ = f.Close() }()
		info, err := f.Stat()
		if err != nil {
			http.Error(w, "media unavailable", http.StatusInternalServerError)
			return
		}
		http.ServeContent(w, r, info.Name(), info.ModTime(), f)
	})
	return mux, nil
}

func transfer(ctx context.Context, o options, e *engine.Engine, k protocol.NodeKey, tr http.RoundTripper) error {
	request := func(path string) (*http.Response, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://peer.invalid"+path, nil)
		if err != nil {
			return nil, err
		}
		if o.mode == "range" {
			r.Header.Set("Range", "bytes=10-15")
		}
		res, err := tr.RoundTrip(r)
		if err == nil && res.StatusCode != http.StatusOK && res.StatusCode != http.StatusPartialContent {
			_ = res.Body.Close()
			return nil, fmt.Errorf("HTTP status %d", res.StatusCode)
		}
		return res, err
	}
	if o.duration == 0 && o.mode != "range" && o.warmupBytes > 0 {
		res, err := request("/random?bytes=" + strconv.FormatInt(o.warmupBytes, 10))
		if err != nil {
			return err
		}
		_, readErr := io.Copy(io.Discard, res.Body)
		if err := errors.Join(readErr, res.Body.Close()); err != nil {
			return err
		}
	}
	path := o.path
	if o.mode == "throughput" {
		count := o.bytes
		if o.duration > 0 {
			count = 1 << 60
		}
		path = "/random?bytes=" + url.QueryEscape(strconv.FormatInt(count, 10))
	}
	res, err := request(path)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	start := time.Now()
	var count int64
	if o.duration > 0 && o.mode == "throughput" {
		buffer := make([]byte, 64<<10)
		warm := true
		for {
			n, readErr := res.Body.Read(buffer)
			now := time.Now()
			if warm && now.Sub(start) >= o.warmup {
				start = now
				warm = false
			} else if !warm {
				count += int64(n)
			}
			if !warm && now.Sub(start) >= o.duration {
				break
			}
			if readErr != nil {
				return fmt.Errorf("timed transfer ended early: %w", readErr)
			}
		}
	} else {
		count, err = io.Copy(io.Discard, res.Body)
		if err != nil {
			return err
		}
		if o.mode == "throughput" && count != o.bytes {
			return fmt.Errorf("received %d bytes, want %d", count, o.bytes)
		}
	}
	elapsed := time.Since(start).Seconds()
	return json.NewEncoder(os.Stdout).Encode(struct {
		Bytes    int64             `json:"bytes"`
		Seconds  float64           `json:"seconds"`
		Goodput  float64           `json:"goodput_mbps"`
		Path     engine.PathStatus `json:"path"`
		Counters engine.Counters   `json:"counters"`
	}{count, elapsed, float64(count) * 8 / elapsed / 1e6, e.Path(k), e.Counters()})
}
