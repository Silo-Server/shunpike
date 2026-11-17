# Shunpike

Shunpike provides a neutral Go engine package with three explicit probes: local UDP socket capabilities, STUN-based NAT observations, and router port-mapping discovery. Its `coordination` packages define the wire protocol, with a revision constant, and a server for device registration, netmaps and signaling. Capability probing sends no packets. Network probes run only when called, and every entry point disables Tailscale network namespace binding.

## Using shunpike

Shunpike builds against patched forks of quic-go and Tailscale. A consumer module must add the same two `replace` lines to its own `go.mod`. Go ignores `replace` directives in a dependency's `go.mod`, so the lines here do not reach the consumer.

```
replace github.com/quic-go/quic-go => github.com/darthShadow/quic-go v0.64.1-shunpike.1

replace tailscale.com => github.com/darthShadow/tailscale v1.104.2-shunpike.1
```

## License

Shunpike is licensed under BSD-3-Clause. See `LICENSE`.
