# Shunpike

Shunpike provides a neutral Go engine package with three explicit probes: local UDP socket capabilities, STUN-based NAT observations, and router port-mapping discovery. Its `coordination` packages define the wire protocol, with a revision constant, and a server for device registration, netmaps and signaling. Capability probing sends no packets. Network probes run only when called, and every entry point disables Tailscale network namespace binding.

This checkout uses sibling quic-go and Tailscale forks through local module replacements.
