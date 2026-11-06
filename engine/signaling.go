package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"
	"tailscale.com/net/wsconn"
)

// ErrNoCredential lets a caller refuse a dial when no current credential exists.
var ErrNoCredential = errors.New("no signaling credential")

func secureURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("signaling requires an HTTPS URL without user information or fragment")
	}
	return nil
}

// WebSocketDialer returns a binary DERP stream dialer. Each attempt calls headers
// afresh; its errors are wrapped. HTTPS, TLS verification and no redirects apply.
// A nil headers function supplies no credential headers. The caller closes streams.
func WebSocketDialer(tlsConfig *tls.Config, headers func(context.Context) (http.Header, error)) func(ctx context.Context, url string) (net.Conn, error) {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if tlsConfig != nil {
		tr.TLSClientConfig = tlsConfig.Clone()
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(ctx context.Context, url string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := secureURL(url); err != nil {
			return nil, err
		}
		var h http.Header
		if headers != nil {
			var err error
			h, err = headers(ctx)
			if err != nil {
				return nil, fmt.Errorf("signaling headers: %w", err)
			}
		}
		c, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPClient: client, HTTPHeader: h, Subprotocols: []string{"derp"}})
		if err != nil {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			return nil, fmt.Errorf("signaling dial: %w", err)
		}
		if c.Subprotocol() != "derp" {
			_ = c.CloseNow()
			return nil, errors.New("signaling requires derp subprotocol")
		}
		return wsconn.NetConn(context.Background(), c, websocket.MessageBinary, url), nil
	}
}
