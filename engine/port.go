package engine

import (
	"errors"
	"fmt"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/Silo-Server/shunpike/coordination/protocol"
)

// ErrPortUnavailable means the requested fixed UDP port could not be bound.
var ErrPortUnavailable = errors.New("requested UDP port unavailable")

func (e *Engine) checkPort(start bool) error {
	bound := e.LocalPort()
	e.mu.Lock()
	changed := bound != e.lastPort
	e.lastPort = bound
	drift := e.config.Port != 0 && bound != e.config.Port
	logDrift := drift && !start && !e.portDriftLogged
	if logDrift {
		e.portDriftLogged = true
	}
	e.mu.Unlock()
	if drift && start {
		return fmt.Errorf("%w: requested %d, bound %d", ErrPortUnavailable, e.config.Port, bound)
	}
	if logDrift && e.config.Logger != nil {
		e.config.Logger.Error("engine port changed", "requested", e.config.Port, "bound", bound)
	}
	if changed || logDrift {
		e.notifyRegistration()
	}
	return nil
}

func (e *Engine) endpointsUpdated(eps []tailcfg.Endpoint) {
	e.mu.Lock()
	changed := !endpointsEqual(e.endpoints, eps)
	e.endpoints = append([]tailcfg.Endpoint(nil), eps...)
	magic := e.magic
	e.mu.Unlock()
	if changed {
		e.notifyRegistration()
	}
	if magic != nil {
		_ = e.checkPort(false)
	}
}

func endpointsEqual(a, b []tailcfg.Endpoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Rebind resets mappings and confirmation evidence, then signals port drift.
func (e *Engine) Rebind() {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.pongs = map[key.NodePublic]protocol.Confirmation{}
	for k, p := range e.peerConfig {
		p.Confirmation = nil
		e.peerConfig[k] = p
	}
	e.mu.Unlock()
	e.notifyRegistration()
	e.magic.Rebind()
	_ = e.checkPort(false)
	e.magic.ReSTUN("engine-explicit-rebind")
}
