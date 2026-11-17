// Package coordclient keeps an engine's registration and peer set current
// against a coordination service.
package coordclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/darthShadow/shunpike/coordination/protocol"
	"github.com/darthShadow/shunpike/engine"
)

const (
	// registrationTimeout bounds one registration request. Netmap requests use
	// protocol.NetmapRequestTimeout, which exceeds the server's longest hold.
	registrationTimeout = 15 * time.Second
	// retryDelay is the wait after the first failed netmap request. Each further
	// consecutive failure doubles it, up to maxRetryDelay.
	retryDelay    = time.Second
	maxRetryDelay = 30 * time.Second
	// maxRetryAfter caps the wait a Retry-After header can ask for.
	maxRetryAfter = time.Minute
	// drainLimit caps the response bytes read from a request whose body the
	// client does not use.
	drainLimit = 4096
)

// Options configures Run.
//
// BaseURL is the HTTPS base of the coordination service. The client appends
// "/registration" and "/netmap" to it; a trailing slash is ignored. It must not
// carry user information, a query or a fragment. When a netmap lists no
// regions, the client gives the engine one region named BaseURL + "/signal"
// with ID 0.
//
// TLSConfig verifies the service; nil selects the platform defaults.
//
// Headers supplies every header of every request, and the client sends no
// other header of its own: it sends no User-Agent and asks for no compression,
// and the only header it adds is the Content-Length of the registration body.
// It is called once per request. Its error fails the
// request and stays wrapped, so an ErrNoCredential result can be matched with
// errors.Is. A nil Headers sends none.
//
// Logger receives warnings about failed requests; nil discards them.
type Options struct {
	BaseURL   string
	TLSConfig *tls.Config
	Headers   func(context.Context) (http.Header, error)
	Logger    *slog.Logger
}

type client struct {
	o       Options
	base    string
	http    *http.Client
	engine  *engine.Engine
	log     *slog.Logger
	refresh atomic.Int64 // nanoseconds; the latest netmap's refresh_seconds
	regions []protocol.Region
	// sleep waits d or until ctx ends, and reports whether the full wait passed.
	sleep func(ctx context.Context, d time.Duration) bool
}

// statusError is a request answered with an unacceptable HTTP status.
type statusError struct {
	op   string
	code int
	// retryAfter is the wait the service asked for; zero when it sent none.
	retryAfter time.Duration
}

func (e *statusError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.op, e.code) }

// parseRetryAfter reads a Retry-After value in seconds or as an HTTP date. It
// returns zero for an absent, malformed or past value.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.ParseUint(v, 10, 32); err == nil {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// sleepFor waits d or until ctx ends, and reports whether the full wait passed.
func sleepFor(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// retryWait returns how long to wait after the failures-th consecutive failure
// (counting from one) when the service asked for retryAfter.
func retryWait(failures int, retryAfter time.Duration) time.Duration {
	wait := maxRetryDelay
	if failures < 6 { // retryDelay<<5 already exceeds maxRetryDelay
		wait = min(retryDelay<<(failures-1), maxRetryDelay)
	}
	return max(wait, min(retryAfter, maxRetryAfter))
}

// Run registers e with the coordination service, applies the first netmap to
// it, and returns. It then keeps running until ctx ends: it registers again
// whenever the engine's registration changes and every refresh_seconds that the
// latest netmap announces, and it long-polls the netmap, applying each one to
// the engine. A netmap's hosts become the engine's peers with a lease that ends
// lease_seconds after the request started, and its regions, or the default
// region, become the engine's signaling regions.
//
// Run fails, without starting workers, when BaseURL is not an acceptable HTTPS
// URL, when the engine is closed, or when the first registration or netmap
// fails. A 401 or 403 answer to any request expires the engine's peers at once.
// After a failed background netmap request the client waits before it asks again:
// one second, doubling with each consecutive failure up to thirty seconds, and
// never less than the service's Retry-After (capped at one minute). After a 429
// answer it keeps the netmap version, so the next request can hold instead of
// returning at once. A failed registration is tried again on the next change or
// refresh.
func Run(ctx context.Context, o Options, e *engine.Engine) error {
	c, err := newClient(o, e)
	if err != nil {
		return err
	}
	reg, err := e.Registration()
	if err != nil {
		return fmt.Errorf("read registration: %w", err)
	}
	if err := c.register(ctx, reg); err != nil {
		c.http.CloseIdleConnections()
		return err
	}
	version, err := c.netmap(ctx, "")
	if err != nil {
		c.http.CloseIdleConnections()
		return err
	}
	var workers sync.WaitGroup
	workers.Go(func() { c.registerLoop(ctx, reg) })
	workers.Go(func() { c.netmapLoop(ctx, version) })
	go func() {
		workers.Wait()
		c.http.CloseIdleConnections()
	}()
	return nil
}

func newClient(o Options, e *engine.Engine) (*client, error) {
	if e == nil {
		return nil, errors.New("coordclient: engine required")
	}
	u, err := url.Parse(o.BaseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("coordclient: BaseURL must be an HTTPS URL without user information, query or fragment")
	}
	transport := &http.Transport{DisableCompression: true}
	if o.TLSConfig != nil {
		transport.TLSClientConfig = o.TLSConfig.Clone()
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &client{
		o:    o,
		base: strings.TrimRight(o.BaseURL, "/"),
		// No cookie jar, no proxy and no redirects: a redirect would carry the
		// credential headers to another place.
		http:   &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		engine: e,
		log:    log,
		sleep:  sleepFor,
	}, nil
}

// newRequest builds a request carrying the headers function's headers only.
func (c *client) newRequest(ctx context.Context, method, target string, body io.Reader) (*http.Request, error) {
	var h http.Header
	if c.o.Headers != nil {
		var err error
		if h, err = c.o.Headers(ctx); err != nil {
			return nil, fmt.Errorf("request headers: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	if h != nil {
		req.Header = h.Clone()
	}
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header["User-Agent"] = []string{""} // An empty value stops the transport adding its own.
	}
	return req, nil
}

// check expires the engine's peers on 401 and 403 and reports any status
// that ok refuses as a *statusError.
func (c *client) check(op string, res *http.Response, ok func(int) bool) error {
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		c.engine.Expire()
	}
	if !ok(res.StatusCode) {
		return &statusError{op: op, code: res.StatusCode, retryAfter: parseRetryAfter(res.Header.Get("Retry-After"), time.Now())}
	}
	return nil
}

func (c *client) register(ctx context.Context, reg protocol.Registration) error {
	body, err := json.Marshal(reg)
	if err != nil {
		return fmt.Errorf("registration: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, registrationTimeout)
	defer cancel()
	req, err := c.newRequest(ctx, http.MethodPost, c.base+"/registration", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("registration: %w", err)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("registration: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, drainLimit))
	return c.check("registration", res, func(code int) bool { return code >= 200 && code < 300 })
}

// netmap requests the netmap, holding until it differs from version when
// version is not empty, applies it to the engine and returns its version.
func (c *client) netmap(ctx context.Context, version string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, protocol.NetmapRequestTimeout)
	defer cancel()
	start := time.Now()
	target := c.base + "/netmap"
	if version != "" {
		target += "?version=" + url.QueryEscape(version)
	}
	req, err := c.newRequest(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", fmt.Errorf("netmap: %w", err)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("netmap: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if err := c.check("netmap", res, func(code int) bool { return code == http.StatusOK }); err != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, drainLimit))
		return "", err
	}
	nm, err := protocol.DecodeNetmap(res.Body)
	if err != nil {
		return "", fmt.Errorf("netmap: %w", err)
	}
	if err := c.apply(nm, start); err != nil {
		return "", err
	}
	c.refresh.Store(int64(time.Duration(nm.RefreshSeconds) * time.Second))
	return nm.Version, nil
}

// apply gives the engine the netmap's regions and hosts. The lease runs from
// start, the moment the request began, so response latency cannot extend it.
// Regions are set only when they change, since a new region set reconnects.
func (c *client) apply(nm protocol.Netmap, start time.Time) error {
	regions := nm.Regions
	if len(regions) == 0 {
		regions = []protocol.Region{{ID: 0, Code: "default", URL: c.base + "/signal"}}
	}
	if !slices.Equal(regions, c.regions) {
		if err := c.engine.SetRegions(regions); err != nil {
			return fmt.Errorf("apply netmap regions: %w", err)
		}
		c.regions = slices.Clone(regions)
	}
	expires := start.Add(time.Duration(nm.LeaseSeconds) * time.Second)
	peers := make([]engine.Peer, 0, len(nm.Hosts))
	for _, h := range nm.Hosts {
		peers = append(peers, engine.Peer{NodeKey: h.NodeKey, DiscoKey: h.DiscoKey, Endpoints: h.Endpoints, HomeRegion: h.HomeRegion, Expires: expires, Confirmation: h.Confirmation})
	}
	if err := c.engine.SetPeers(peers); err != nil {
		return fmt.Errorf("apply netmap peers: %w", err)
	}
	return nil
}

// registerLoop registers when the engine reports a change that alters the
// registration, and every refresh interval whether or not it changed. last is
// the registration the service holds.
func (c *client) registerLoop(ctx context.Context, last protocol.Registration) {
	interval := time.Duration(c.refresh.Load())
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		due := false
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			due = true
		case <-c.engine.Changed():
		}
		if d := time.Duration(c.refresh.Load()); d != interval {
			interval = d
			tick.Reset(d)
		}
		reg, err := c.engine.Registration()
		if err != nil {
			return // the engine is closed
		}
		if !due && sameRegistration(reg, last) {
			continue
		}
		if err := c.register(ctx, reg); err != nil {
			if ctx.Err() == nil {
				c.log.Warn("coordination registration failed", "error", err)
			}
			continue
		}
		last = reg
	}
}

func sameRegistration(a, b protocol.Registration) bool {
	return a.NodeKey == b.NodeKey && a.DiscoKey == b.DiscoKey && slices.Equal(a.Endpoints, b.Endpoints) && slices.Equal(a.Confirmations, b.Confirmations)
}

// netmapLoop long-polls the netmap. After a failure it waits retryWait. After
// a 429 answer it keeps the version, so the next request holds until the view
// changes. After any other failure it forgets the version, so the next request
// returns the current netmap at once.
func (c *client) netmapLoop(ctx context.Context, version string) {
	failures := 0
	for ctx.Err() == nil {
		v, err := c.netmap(ctx, version)
		if err == nil {
			version = v
			failures = 0
			continue
		}
		if ctx.Err() != nil {
			return
		}
		var status *statusError
		if !errors.As(err, &status) || status.code != http.StatusTooManyRequests {
			version = ""
		}
		failures++
		var retryAfter time.Duration
		if status != nil {
			retryAfter = status.retryAfter
		}
		c.log.Warn("coordination netmap failed", "error", err)
		if !c.sleep(ctx, retryWait(failures, retryAfter)) {
			return
		}
	}
}
