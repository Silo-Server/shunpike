package engine

import (
	"context"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

// TestWebSocketDialerReadsNoProxyEnvironment starts a child test process whose
// environment names a proxy, and checks that the child's dial never reaches it.
// A child is needed because the standard library reads proxy variables once per
// process. The target host is not a loopback name, which proxy variables skip.
func TestWebSocketDialerReadsNoProxyEnvironment(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var hits atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			_ = c.Close()
		}
	}()
	proxy := "http://" + ln.Addr().String()
	cmd := exec.Command(os.Args[0], "-test.run=^TestWebSocketDialerProxyChild$", "-test.count=1")
	cmd.Env = []string{"HTTPS_PROXY=" + proxy, "https_proxy=" + proxy, "HTTP_PROXY=" + proxy, "http_proxy=" + proxy, "NO_PROXY=", "no_proxy="}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child test: %v\n%s", err, out)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("dialer connected to the proxy named in the environment %d times, want 0", got)
	}
}

// TestWebSocketDialerProxyChild is the child of the test above. Run alone, it
// checks that a dial to an unresolvable host fails.
func TestWebSocketDialerProxyChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := WebSocketDialer(nil, nil)(ctx, "https://region.invalid/signal"); err == nil {
		t.Fatal("dial to an unresolvable host succeeded")
	}
}
