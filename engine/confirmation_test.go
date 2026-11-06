package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/darthShadow/shunpike/coordination/protocol"
)

// Only the disco network boundary is replaced; Engine.Ping and confirmation
// publication use their real implementation, with synctest's virtual clock.
type confirmationDisco struct {
	ping   func(tailcfg.NodeView, *ipnstate.PingResult, int, func(*ipnstate.PingResult))
	key    key.DiscoPublic
	status func(*ipnstate.StatusBuilder)
}

func (d *confirmationDisco) Ping(n tailcfg.NodeView, r *ipnstate.PingResult, size int, cb func(*ipnstate.PingResult)) {
	d.ping(n, r, size, cb)
}
func (d *confirmationDisco) DiscoPublicKey() key.DiscoPublic { return d.key }
func (d *confirmationDisco) UpdateStatus(sb *ipnstate.StatusBuilder) {
	if d.status != nil {
		d.status(sb)
	}
}

func confirmationEngine(count int) (*Engine, []key.NodePublic) {
	e := newEngineState(Config{PrivateKey: NodePrivateFromBytes(key.NewNode().Raw32())})
	e.disco = &confirmationDisco{key: key.NewDisco().Public()}
	var keys []key.NodePublic
	for range count {
		n := &tailcfg.Node{Key: key.NewNode().Public(), DiscoKey: key.NewDisco().Public()}
		e.peers[n.Key] = n.View()
		e.peerConfig[n.Key] = Peer{NodeKey: nodeKey(n.Key), DiscoKey: discoKey(n.DiscoKey), Expires: time.Now().Add(time.Minute)}
		e.discovery[n.Key] = directDiscovery{first: time.Now()}
		keys = append(keys, n.Key)
	}
	return e, keys
}

func TestSlowPeerDoesNotDelayConfirmation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, keys := confirmationEngine(2)
		e.disco.(*confirmationDisco).ping = func(n tailcfg.NodeView, _ *ipnstate.PingResult, _ int, cb func(*ipnstate.PingResult)) {
			if n.Key() == keys[1] {
				cb(&ipnstate.PingResult{Endpoint: "192.0.2.1:41641"})
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { defer close(done); e.probePeers(ctx, keys) }()
		defer func() { cancel(); <-done }()
		synctest.Wait()
		if confirmationStatus(e, keys[1]).Pong == nil {
			t.Fatal("responsive peer has no confirmation while the first peer waits")
		}
	})
}

func TestConfirmationProbeConcurrencyIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, keys := confirmationEngine(80)
		started := make(chan key.NodePublic, len(keys))
		e.disco.(*confirmationDisco).ping = func(n tailcfg.NodeView, _ *ipnstate.PingResult, _ int, _ func(*ipnstate.PingResult)) {
			started <- n.Key()
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { defer close(done); e.probePeers(ctx, keys) }()
		defer func() { cancel(); <-done }()
		synctest.Wait()
		if got := len(started); got != 32 {
			t.Fatalf("in-flight probes=%d, want bounded pool of 32", got)
		}
		cancel()
		<-done
		if got := len(started); got != 32 {
			t.Fatalf("probes after cancellation=%d, want 32", got)
		}
	})
}

func TestConfirmationSurvivesSingleTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, keys := confirmationEngine(1)
		k := keys[0]
		e.recordPong(k, e.peer(k).DiscoKey(), &ipnstate.PingResult{Endpoint: "192.0.2.1:41641"})
		e.disco.(*confirmationDisco).ping = func(tailcfg.NodeView, *ipnstate.PingResult, int, func(*ipnstate.PingResult)) {}
		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()
		if _, err := e.ping(ctx, k); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Ping error=%v, want deadline exceeded", err)
		}
		if confirmationStatus(e, k).Pong == nil {
			t.Fatal("one 500 ms timeout erased a fresh direct confirmation")
		}
	})
}

func TestConfirmationExpiresByAge(t *testing.T) {
	for _, observer := range []string{"path", "registration"} {
		t.Run(observer, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e, keys := confirmationEngine(1)
				k := keys[0]
				e.recordPong(k, e.peer(k).DiscoKey(), &ipnstate.PingResult{Endpoint: "192.0.2.1:41641"})
				time.Sleep(999 * time.Millisecond)
				if confirmationStatus(e, k).Pong == nil {
					t.Fatal("confirmation expired before its 1 second lifetime")
				}
				<-e.endpointChanged
				time.Sleep(time.Millisecond)
				if observer == "path" {
					if confirmationStatus(e, k).Pong != nil {
						t.Fatal("aged confirmation still appears in path status")
					}
				} else {
					r, err := e.Registration()
					if err != nil {
						t.Fatal(err)
					}
					if slices.ContainsFunc(r.Confirmations, func(c protocol.Confirmation) bool { return c.Peer == nodeKey(k) }) {
						t.Fatal("aged confirmation still published to the peer")
					}
				}
				select {
				case <-e.endpointChanged:
				default:
					t.Fatal("expiration did not wake registration")
				}
			})
		})
	}
}

func TestConfirmationRetriesAndKeepsLiveness(t *testing.T) {
	e, keys := confirmationEngine(1)
	calls := 0
	e.disco.(*confirmationDisco).ping = func(_ tailcfg.NodeView, _ *ipnstate.PingResult, _ int, cb func(*ipnstate.PingResult)) {
		calls++
		p := &ipnstate.PingResult{Endpoint: "192.0.2.1:41641"}
		if calls == 1 {
			p.DERPRegionID = 1
		}
		cb(p)
	}
	e.probePeers(t.Context(), keys)
	if confirmationStatus(e, keys[0]).Pong != nil {
		t.Fatal("non-direct reply confirmed a direct path")
	}
	e.probePeers(t.Context(), keys)
	if confirmationStatus(e, keys[0]).Pong == nil {
		t.Fatal("retry failed to confirm direct path")
	}
	e.probePeers(t.Context(), keys)
	if calls != 3 {
		t.Fatalf("probes=%d, want 3 including liveness after confirmation", calls)
	}
}

func TestConfirmationKeepsHealthyPathDirect(t *testing.T) {
	for _, role := range []string{"client", "server"} {
		t.Run(role, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e, keys := confirmationEngine(1)
				// The same confirmation rule applies to either role.
				k := keys[0]
				d := e.disco.(*confirmationDisco)
				d.status = func(sb *ipnstate.StatusBuilder) {
					sb.AddPeer(k, &ipnstate.PeerStatus{CurAddr: "192.0.2.20:41641"})
				}
				d.ping = func(_ tailcfg.NodeView, _ *ipnstate.PingResult, _ int, cb func(*ipnstate.PingResult)) {
					cb(&ipnstate.PingResult{Endpoint: "192.0.2.20:41641"})
				}
				e.probePeers(t.Context(), keys)
				for sample := 0; sample <= 120; sample++ {
					if got := confirmationStatus(e, k).ObservedPath(); got != "direct" {
						t.Fatalf("healthy %s path at %s=%q, want direct", role, time.Duration(sample)*25*time.Millisecond, got)
					}
					if sample%20 == 0 {
						e.probePeers(t.Context(), keys)
					}
					time.Sleep(25 * time.Millisecond)
				}
			})
		})
	}
}

func TestConfirmationRevokesLostReplies(t *testing.T) {
	for _, role := range []string{"client", "server"} {
		t.Run(role, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e, keys := confirmationEngine(1)
				// The same confirmation rule applies to either role.
				k := keys[0]
				d := e.disco.(*confirmationDisco)
				d.status = func(sb *ipnstate.StatusBuilder) {
					sb.AddPeer(k, &ipnstate.PeerStatus{CurAddr: "192.0.2.20:41641"})
				}
				d.ping = func(_ tailcfg.NodeView, _ *ipnstate.PingResult, _ int, cb func(*ipnstate.PingResult)) {
					cb(&ipnstate.PingResult{Endpoint: "192.0.2.20:41641"})
				}
				e.probePeers(t.Context(), keys)
				if got := confirmationStatus(e, k).ObservedPath(); got != "direct" {
					t.Fatalf("initial path=%q, want direct", got)
				}
				d.ping = func(tailcfg.NodeView, *ipnstate.PingResult, int, func(*ipnstate.PingResult)) {}
				time.Sleep(500 * time.Millisecond)
				e.probePeers(t.Context(), keys)
				time.Sleep(500 * time.Millisecond)
				e.probePeers(t.Context(), keys)
				if got := confirmationStatus(e, k).ObservedPath(); got != "none" {
					t.Fatalf("%s path after lost replies=%q, want unknown within 2 seconds", role, got)
				}
			})
		})
	}
}

func TestConfirmationRejectsStaleCallbacks(t *testing.T) {
	for _, invalidate := range []string{"disco", "removal", "lease", "close"} {
		t.Run(invalidate, func(t *testing.T) {
			e, keys := confirmationEngine(1)
			k := keys[0]
			disco := e.peer(k).DiscoKey()
			switch invalidate {
			case "disco":
				n := e.peer(k).AsStruct()
				n.DiscoKey = key.NewDisco().Public()
				e.peers[k] = n.View()
			case "removal":
				delete(e.peers, k)
			case "lease":
				p := e.peerConfig[k]
				p.Expires = time.Now()
				e.peerConfig[k] = p
			case "close":
				e.closed = true
			}
			e.recordPong(k, disco, &ipnstate.PingResult{Endpoint: "192.0.2.1:41641"})
			if confirmationStatus(e, k).Pong != nil {
				t.Fatal("stale callback restored direct confirmation")
			}
		})
	}
}

// confirmationStatus retains the original confirmation assertions while using
// the public path enum and the protocol's smaller confirmation identity.
func confirmationStatus(e *Engine, k key.NodePublic) confirmationObservation {
	s := e.Path(nodeKey(k))
	e.mu.Lock()
	c, ok := e.confirmedPongLocked(k)
	e.mu.Unlock()
	o := confirmationObservation{class: string(s.Class)}
	if ok {
		o.Pong = &ipnstate.PingResult{Endpoint: c.Endpoint.String()}
	}
	return o
}

type confirmationObservation struct {
	Pong  *ipnstate.PingResult
	class string
}

func (o confirmationObservation) ObservedPath() string { return o.class }

func TestRegistrationKeepsFirstSixtyFourConfirmations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, keys := confirmationEngine(65)
		var want []protocol.NodeKey
		for i, k := range keys {
			e.recordPong(k, e.peer(k).DiscoKey(), &ipnstate.PingResult{Endpoint: fmt.Sprintf("192.0.2.1:%d", 41641+i)})
			want = append(want, nodeKey(k))
		}
		slices.SortFunc(want, func(a, b protocol.NodeKey) int { return slices.Compare(a[:], b[:]) })
		r, err := e.Registration()
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Confirmations) != 64 {
			t.Fatalf("confirmations=%d, want 64", len(r.Confirmations))
		}
		for i, c := range r.Confirmations {
			if c.Peer != want[i] {
				t.Fatalf("confirmation %d peer=%v, want %v", i, c.Peer, want[i])
			}
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("Registration fails its wire validator: %v", err)
		}
	})
}
