package engine

import "github.com/darthShadow/shunpike/coordination/protocol"

// Addr identifies a node independently of its current UDP endpoint.
type Addr struct{ Key protocol.NodeKey }

// Network returns the logical transport name.
func (Addr) Network() string { return "shunpike" }

// String returns the node's canonical public key.
func (a Addr) String() string { return a.Key.String() }
