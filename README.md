# Shunpike

Shunpike v0.1 provides a neutral Go engine package with three explicit probes: local UDP socket capabilities, STUN-based NAT observations, and router port-mapping discovery. Capability probing sends no packets. Network probes run only when called, and every entry point disables Tailscale network namespace binding.

This checkout uses sibling quic-go and Tailscale forks through local module replacements.
