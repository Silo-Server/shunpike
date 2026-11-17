# Coordination Wire Protocol

The protocol publishes discovery identities, endpoints and direct-path
confirmations. It carries signaling for direct transport. Authentication and
account policy belong to the embedding application. The protocol package uses
only the Go standard library and reads no environment variables.

## Operations

The embedding application verifies credentials before it registers a device or
returns its netmap. Registration publishes the authenticated device's current
discovery state. Netmap returns the hosts that device may contact. A netmap may
be held until its content changes or the hold expires. Signaling uses a WebSocket
with subprotocol `derp`; the application supplies all credential headers.
Enrollment and withdrawal are application-authorized operations. Withdrawal
removes the device's presence and closes its signaling connection.

The HTTP wrapper supplies routes and authentication. Clients append
`registration`, `netmap` and `signal` to their configured base URL. These wire
types do not define credentials, account identifiers or deployment-specific
header names.

## JSON Messages

Keys are JSON strings: `nodekey:` or `discokey:` followed by exactly 64 lowercase
hex digits. They represent 32 public-key bytes, not private keys. Wrong prefixes,
uppercase hex and wrong lengths are invalid. A syntactically valid all-zero key
cannot identify a node or discovery identity in a message. UDP endpoints use
`netip.AddrPort` text: `192.0.2.1:443` or `[2001:db8::1]:443`.

| Object | Fields |
|---|---|
| Confirmation | `peer` (node key), `disco_key` (discovery key), `endpoint` (UDP address and port) |
| Registration | `node_key`, `disco_key`, `endpoints` (array), optional `confirmations` (array) |
| Region | `id` (integer), `code` (string), `url` (absolute HTTPS signaling URL) |
| Host | `label`, `node_key`, `disco_key`, `endpoints` (array), `home_region` (integer), optional `origin` (opaque string), optional `confirmation` (object) |
| Netmap | `version` (string), `lease_seconds` (integer), `refresh_seconds` (integer), optional `regions` (array), `hosts` (array) |

The JSON files in `vectors/` contain complete examples and refused inputs. Each
document vector has `name`, `body` and `want` (`accept`, `invalid` or
`too_large`). `suffix` appends trailing text; `size` pads the encoded body with
spaces to the exact byte count. `decode_only` identifies a check on encoding
rather than on the Go value.

Registration and netmap decoders require exactly one JSON object. Unknown fields
at every nesting level and trailing non-whitespace data are invalid. Byte limits
include whitespace and trailing data. `ErrTooLarge` identifies excess bytes;
`ErrInvalid` identifies malformed encoding or invalid fields. Reader failures
preserve their underlying error. Decoding failure returns a zero message.
Field names match case-insensitively, as Go's `encoding/json` does.

## Validation and Conversion

A registration requires nonzero node and discovery keys. Endpoints have a
nonzero port and a valid address that is neither unspecified nor multicast.
IPv4 and IPv6 are valid, including private and loopback unicast addresses.
Confirmations have nonzero peer and discovery keys and a valid UDP endpoint;
their peer is unique within a registration and differs from the registering
node. An empty endpoint or confirmation list is valid.

Each host has a valid label, a nonzero node key and a nonzero discovery key.
Labels and node keys are unique in a netmap. Region identifiers are unique and
their URLs use HTTPS. Each host's `home_region` references a listed region. With
no regions, the client uses one region at `BaseURL + "/signal"` and every
`home_region` is 0. Empty and omitted `regions` have the same meaning.

A host's confirmation describes its observation of the requesting device, so
the confirmation peer differs from the host's node key. The protocol validates
the confirmation's keys and endpoint. The consumer, which knows its own keys,
also checks that the confirmation peer and discovery key match its current
identity. Registration admission checks confirmation identities against the
authorized peer directory. The message alone does not contain that directory.

Key conversion at the transport boundary uses the canonical text methods.
Transport-specific key types stay out of this package. Confirmations contain
only `(peer, disco_key, endpoint)`. Repeated observations of the same identity
renew presence without changing the netmap version or waking a held request.
TLS pins come from deployment configuration, and devices already know their own
keys; neither is repeated in the netmap.

## Limits and Timings

| Item | Limit or Default |
|---|---|
| Registration body | 64 KiB (65,536 bytes) |
| Netmap body | 1 MiB (1,048,576 bytes) |
| Endpoints per registration or host | 64 |
| Confirmations per registration | 64 |
| Hosts per netmap | 256 |
| Host label | 1-64 bytes of `[a-z0-9._:-]` |
| `lease_seconds` | 10-600; default 90 |
| `refresh_seconds` | 1 to `lease_seconds`/3, using integer division; default 30 |
| Server netmap hold | Default 25 s; below `NetmapRequestTimeout` |
| Server presence | Default 90 s |
| Client netmap request timeout | `NetmapRequestTimeout`, 35 s |
| Discovery body after destination key | At most 1,280 bytes |
| ClientInfo body | At least 72 bytes |
| Pair frame bucket | Burst 20; refill 5 per s |
| Pair byte bucket | Burst 25,600 bytes; refill 6,400 bytes per s |
| Consecutive budget overruns before close | 3 |
| Connection byte window | 1 MiB per 90 s |

The pair frame bucket, pair byte bucket and connection byte window rows are
defaults. `protocol.BudgetLimits` replaces any of them: set it as
`Budget.Limits` for `CheckFrame`, or as `RegionOptions.Budget.Limits` for a
region. A zero or negative field keeps its default, and the zero value keeps all
of them. The five fields are the pair frame burst and refill rate, the pair byte
burst and refill rate, and the connection byte limit; the 90 s window and the
three-overrun close are fixed. The stream that `Region.DialLocal` returns carries
every pair of its host, so its byte total grows with the number of devices.
`RegionOptions.LocalConnectionBytes` sets that stream's connection byte limit
apart from the devices' limit, and `LocalConnectionBytesPerPair` raises it to
that many bytes for each pair that carried a frame in the current 90 s window when
the product is larger; zero keeps the shared limit. A pair that expires in the
window still counts until the window ends, so the limit never falls within a
window; the next window counts only the pairs that carry a frame in it. CheckFrame
takes such a limit through `Budget.ConnectionLimit`.

Server defaults describe the coordination service; the wire validators check
the announced values and do not insert defaults. A consumer starts its lease
at the request's start so response latency cannot extend authorization.

## Protocol Revision

`ProtocolRevision` is an opaque string, currently `"1"`. A consumer that
publishes or checks it compares for exact equality only; it assumes no order
between values. A client uses the direct path only when the revision it
receives equals a value it knows. A change to the wire shapes, limits or decoder
rules in this package, to signaling or discovery behavior, or to the N4 transport
(QUIC v1, HTTP/3 with `h3`, TLS 1.3 pinned by `tls_pin`), needs a new value.

## Netmap Version

`NetmapVersion` is unpadded base64url of SHA-256 over compact canonical JSON.
The `version` field is present as an empty string during hashing. The fixed Go
struct field order in `protocol/types.go` defines JSON field order, including
the documented `omitempty` fields and Go JSON escaping. Hosts sort by label,
then node-key bytes; regions sort by numeric ID; host endpoints sort by
`netip.AddrPort.Compare` (address, then port). These sorts operate on copies.
Nil and empty hosts and host endpoints hash as `[]`.
No caller-owned slice changes. Non-version field changes change the hash;
input iteration order and the supplied version do not.

The hash does not grant authority. A consumer validates a received message and
applies its credential and lease rules before using it.

## Signaling Envelope

`CheckFrame` consumes the frame type and body after transport decoding. Its
caller supplies authenticated sender discovery bytes, whether this is the first
frame, decrypted ClientInfo JSON, a current authorization decision for the pair,
a mutable budget and clock milliseconds. The caller serializes budget access.
It must not relabel subsequent frames as first frames. Transport authentication,
destination lookup and connection lifecycle belong to the caller.

The zero-value `Budget` uses its own pair and connection state. To share limits,
set `Budget.Pair` to one shared `Budget` for the normalized authorized pair,
including both directions, and `Budget.Connection` to one shared `Budget` for
the connection. These fields select storage directly, without following another
selector. `Budget.Limits` is read from the `Budget` passed to `CheckFrame`, never
from the storage `Pair` or `Connection` selects, so every `Budget` passed for one
traffic stream carries the same limits. A new connection uses new connection
state while retaining live pair state. This keeps a connection's total
independent of how many pairs it carries.

| Frame Type | Rule |
|---|---|
| 2, ClientInfo | First frame only, at least 72 bytes, valid decrypted JSON and empty or absent `meshKey` |
| 4, SendPacket | 32-byte destination followed by at most 1,280 bytes of discovery data |
| 7, NotePreferred | Exactly one byte, 0 or 1 |
| 18 and 19, Ping and Pong | Exactly eight bytes |
| Every other type | Close the connection |

Discovery data is at least 78 bytes, starts with the six bytes
`54 53 f0 9f 92 ac`, and contains the sender's 32-byte discovery key at
offsets 6-37. An inactive pair drops the frame. A sender-key mismatch drops the
frame. Invalid discovery structure closes the connection.

`Verdict.Action` is `accept`, `drop` or `close`. An accepted frame has an empty
reason. Refusal reasons are `client_info`, `mesh`, `size`, `disco`, `pair`,
`sender`, `preferred`, `ping`, `type`, `budget` and `connection_budget`.

After structural and authorization checks, accepted control frames spend one
frame token and `len(body) + 5` byte tokens. The five bytes are the frame header.
ClientInfo bypasses the pair buckets but counts toward the connection window.
Pair buckets refill continuously and never exceed their bursts. The first two
consecutive overruns drop; the third closes. An accepted budgeted frame resets
the overrun count. All observed frame bytes count toward the connection window,
including refused frames. A new 90 s window resets that byte count.

The sustained pair allowance is 6,400 B/s, or 51.2 kbit/s, well under
100 kbit/s. This bounds control traffic, with a separate initial burst allowance.
The envelope does not carry bulk application data and cannot inspect encrypted
discovery contents beyond their public header. The 24 envelope vectors specify
the exact frame decisions and budget thresholds.
