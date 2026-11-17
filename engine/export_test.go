package engine

// ChangePort moves the engine's UDP socket to port and refreshes its endpoints,
// as an operating-system rebind onto another port would. Tests use it because
// Rebind alone keeps the port.
func (e *Engine) ChangePort(port uint16) {
	e.magic.SetPreferredPort(port)
	e.Rebind()
}

// LogDiscovery makes magicsock write its discovery-message log lines to the
// engine's logger, so tests can time them.
func (e *Engine) LogDiscovery() { e.magic.SetDebugLoggingEnabled(true) }
