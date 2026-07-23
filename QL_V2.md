# QuantumLink V2

QuantumLink V2 is a peer-to-peer protocol for authenticated encrypted sessions carrying multiplexed duplex byte streams.

It operates on whole QL records. Packetization, fragmentation, batching, and reassembly belong to the transport adapter, not to QLv2 itself.

## Design goals
1. [Ephemeral peer sessions](#handshake): short-lived keys for encryption
2. [Forward secrecy](#security-properties): losing a long-term private key does not reveal old session data
3. [Minimal authenticated header](#record-and-frame-wire-format): keep routing visible, but authenticated
4. [QL-level reliability](#acknowledgment-and-retransmission): `ack` means received, decrypted, and accepted
5. [Duplex byte streams](#streams): avoid cross-stream head-of-line blocking and keep backpressure local
6. [Efficient wire format](#record-and-frame-wire-format): keep steady-state traffic compact
7. [Hardware-backed cryptography](#security-properties): allow platform-specific crypto implementations
8. Shared core state machine: keep implementation consistent across platforms

## Non-goals

QLv2 is not:

- a packet framing format
- a generic reliability layer for arbitrary raw datagrams
- a globally ordered message bus

## Core terms

- `peer`: one QLv2 endpoint
- `QID`: a stable 16-byte peer identifier
- `peer bundle`: public peer information: `version`, `qid`, `capabilities`, and ML-KEM public key
- `pairing token`: an out-of-band secret that authorizes an `XX` pairing attempt
- `pairing_id`: the visible identifier derived from a pairing token and carried on `XX` records
- `session`: one live encrypted channel with directional keys and directional connection IDs
- `record`: one complete QLv2 wire unit
- `frame`: one logical item inside a session record
- `stream`: one duplex byte stream inside a session
- `route_id`: the application route carried once on the first initiator `StreamData` frame for a stream
- `stream origin`: the peer that opened the stream
- `origin lane`: bytes sent by the stream origin
- `return lane`: bytes sent back toward the stream origin

## Record And Frame Wire Format

QLv2 has two record types:

- `handshake record`: used only during setup
- `session record`: used after the handshake completes

Handshake records are large because they carry ML-KEM material. Session records are small and can carry multiple frames, including frames for different streams.

All whole-record sizes below include the outer 2-byte record header: `version` plus `record type`.

QLv2 uses QUIC-style variable-length integers for several steady-state fields. A varint is 1, 2, 4, or 8 bytes and can represent values in the range `0..2^62-1`. This keeps small values compact while allowing very large record and stream number spaces.

Today, varints are used for:

- session record `seq`
- `Ack.largest_acked`
- `Ack.block_count`
- `Ack.first_range_len`
- `Ack.gap`
- `Ack.range_len`
- `StreamData.stream_id`
- `StreamData.offset`
- `StreamData.route_id` when present
- `StreamData.bytes_len`
- `StreamWindow.stream_id`
- `StreamWindow.maximum_offset`
- `StreamReset.stream_id`

### Handshake records

QLv2 has two routed known-peer handshakes and one pairing handshake:

- `IK` and `KK` carry a visible `sender` and `recipient` QID
- `XX` carries a visible `pairing_id`

#### IK

Used when the initiator already knows the responder bundle.

| Record | Size | Purpose |
| --- | ---: | --- |
| `IK1` | 4785 bytes | start a handshake toward a known responder |
| `IK2` | 3195 bytes | complete `IK` and establish the session |

#### KK

Used when both peers already know each other.

| Record | Size | Purpose |
| --- | ---: | --- |
| `KK1` | 3179 bytes | start a handshake between already-known peers |
| `KK2` | 3195 bytes | complete `KK` and establish the session |

#### XX

Used when the initiator has received an out of band pairing token, and neither peer knows each other.

| Record | Size | Purpose |
| --- | ---: | --- |
| `XX1` | 1595 bytes | start pairing |
| `XX2` | 3201 bytes | send responder static identity and ciphertext |
| `XX3` | 3217 bytes | send initiator static identity and ciphertext |
| `XX4` | 1611 bytes | complete `XX` and establish the session |

### Session records

`session record size = 35..42 + sum(frame sizes)`

There is no explicit AEAD nonce on the wire. The record `seq` is used to derive the nonce.

| Fixed part | Size | Purpose |
| --- | ---: | --- |
| version | 1 byte | protocol version |
| record type | 1 byte | identifies a session record |
| `connection_id` | 16 bytes | route the record to the current session |
| `seq` | 1..8 bytes | varint record identity for ack and retransmit |
| AEAD auth tag | 16 bytes | authenticate the encrypted body |
| fixed overhead total | 35..42 bytes | overhead before any frames |

The visible session header is authenticated as AEAD AAD but is not encrypted.

### Session frames

| Frame | Size | Purpose |
| --- | ---: | --- |
| `Ping` | 1 byte | keep the session alive when idle |
| `Unpair` | 1 byte | forget the currently bound peer and abort the session |
| `Ack` | `4+` bytes | acknowledge received session records with ACK ranges |
| `StreamWindow` | `3..17` bytes | extend per-stream send credit |
| `StreamReset` | `5..12` bytes | abort one stream lane or both lanes |
| `Close` | 3 bytes | close the whole session |
| `StreamData` | `5..34 + payload_len` bytes | carry stream bytes, optional opener route, and optional `fin` |

`StreamData` is the main steady-state frame:

`1 kind + varint(stream_id) + varint(offset) + 1 flags + optional varint(route_id) + varint(bytes_len) + payload_len`

The flags byte carries:

- `fin`
- `header present`

Some useful minimum whole-record sizes for single-frame records:

| Record | Size | Meaning |
| --- | ---: | --- |
| `Ping` only | 36 bytes | idle keepalive |
| `Unpair` only | 36 bytes | peer unpair |
| `Ack` only | 39 bytes | smallest selective ack |
| `Close` only | 38 bytes | session shutdown |
| empty `StreamData` without route header | 40 bytes | empty data or empty `fin` on an existing stream |
| empty opener `StreamData` with a 1-byte `route_id` | 41 bytes | open a new stream without payload bytes |

## Handshake

QLv2 currently supports three Noise-style handshake patterns:

- `IK`: 2 messages, initiator already knows the responder bundle
- `KK`: 2 messages, both peers already know each other
- `XX`: 4 messages, peers authenticate through an out-of-band pairing token and exchange static identity during the handshake

The handshake covers peer authentication and session establishment.

Each successful handshake does five things:

1. authenticate which peer we are talking to
2. derive a fresh transmit key and receive key
3. derive a directional transmit `connection_id` and receive `connection_id`
4. bind transport parameters into the transcript
5. produce a `handshake_hash` for the completed exchange

Today the only transport parameter is:

- initial per-stream receive window

Future transport parameters could include session-wide byte credit or record-size limits.

Each handshake attempt carries:

- `handshake_id`: identifies one attempt and lets stale replies be ignored
- transport parameters

`valid_until` is not currently part of the wire format. Handshake attempts instead expire by local timer.

### Pattern summary

- `IK` lets the responder learn the initiator during handshake completion. The initiator still needs the responder bundle before it can start.
- `KK` requires both peers to already know each other.
- `XX` requires the responder to be armed for pairing and to recognize the visible `pairing_id` derived from the expected pairing token.

### Handshake rules

- attempts are identified by `handshake_id`
- handshake messages are not retransmitted in place
- simultaneous starts must converge deterministically
- if `IK` and `KK` race, `IK` wins
- same-pattern races break ties by ordering the initial ephemeral public keys
- `XX` requires out-of-band authorization and uses visible `pairing_id` for lookup

### Session establishment points

- `IK` and `KK` complete after message 2 (1 RT)
- `XX` completes after 4 messages (2 RTT)

## Session Model

After the handshake, peers exchange encrypted session records.

Each session record has:

- one visible `connection_id`
- one visible `seq`
- one encrypted body containing one or more frames

One session record may carry:

- only control frames
- only stream data
- a mixture of frames for multiple streams

This is the core steady-state model: records are the encrypted transport unit, frames are the logical items inside them.

## Acknowledgment And Retransmission

`Ack` is record-level, not stream-level.

An `Ack` means the peer:

- received that session record
- decrypted it with the current session key
- accepted its `seq`

The ACK wire format is range-based, not bitmap-based. It carries:

- `largest_acked`
- `block_count`
- `first_range_len`
- zero or more `(gap, range_len)` blocks

Ranges are encoded from highest sequence numbers down to lowest sequence numbers.

Receivers track a recent accepted record window so they can:

- reject duplicates
- ignore records that are too old
- emit selective ACK ranges

Pending ACK state is also range-based. If there are too many disjoint ranges, older low ranges may be dropped. An emitted ACK may also be truncated by the remaining record budget.

Retransmission works at the frame level:

- every emitted session record gets a fresh `seq`
- retransmit timers start only after the local transport confirms that it accepted the write
- if a record is considered lost, the FSM restores its frames
- those frames are packed into a new record with a new `seq`

QLv2 does not resend the same logical record identity.

There is no explicit `Nack` frame. Loss is inferred from timeout or from later ACK state that no longer includes a record.

Pure ACK-only records are fire-and-forget: they are not themselves retransmitted.

Example:

`seq = 10`

| Frame | Contents |
| --- | --- |
| `StreamData` | `stream_id=4 offset=0 bytes="hello"` |

The sender receives more bytes for that stream before `seq = 10` is acked:

| Pending new frame | Contents |
| --- | --- |
| `StreamData` | `stream_id=4 offset=5 bytes=" world"` |

If `seq = 10` is considered lost, its frame is restored and packed again with a new record sequence:

`seq = 11`

| Frame | Contents |
| --- | --- |
| `StreamData` | `stream_id=4 offset=0 bytes="hello"` |
| `StreamData` | `stream_id=4 offset=5 bytes=" world"` |

## Streams

Streams are the application primitive.

A stream has two independent lanes:

- origin lane
- return lane

Important properties:

- either peer can open a stream
- stream IDs are split by parity derived from QID ordering, so both peers can open streams without collision
- stream IDs increase monotonically within each parity namespace and must not repeat within a session
- ordering is preserved within a stream lane
- different streams can make progress independently
- record loss on one stream does not block unrelated streams

There is no separate open frame.

Locally, opening a stream allocates:

- a new `stream_id`
- an application `route_id`

On the wire, the stream opener carries that `route_id` once, in the first initiator `StreamData` frame at `offset = 0`, using the optional `StreamHeader`.

`StreamData` carries:

- `stream_id`
- `offset`
- optional `StreamHeader { route_id }`
- `fin`
- bytes

`StreamHeader` is only valid on the first initiator `StreamData` frame for a stream, at `offset = 0`.

`fin` is graceful completion of one lane. It says "no more bytes on this lane" without aborting the other lane.

## Flow Control

Flow control is per stream.

During the handshake, each peer advertises an initial per-stream receive window. That becomes the initial send credit the remote peer can use on each stream.

`StreamWindow` extends that credit by advertising a larger absolute `maximum_offset`.

In practice, a stream is writable only when both are true:

- local send buffering has room
- peer-advertised stream credit allows more bytes

Receive credit advances when the local application commits read bytes, not merely when bytes become readable. That is when the FSM emits a `StreamWindow` update.

## Close And Liveness

`StreamReset` aborts a stream early. Semantically it can target:

- the origin lane
- the return lane
- both lanes

`Close` aborts the whole session.

`Unpair` is stronger than `Close`:

- it forgets the currently bound peer locally
- it aborts the active session immediately
- it may emit one final outbound `Unpair` frame
- reconnect does not resume until a peer is paired again

Idle sessions may send `Ping`. The peer does not answer with another ping; normal record acknowledgment is enough.

Sessions also have local timers for:

- handshake timeout
- delayed ack emission
- session record retransmit timeout
- keepalive ping interval
- peer silence timeout

If peer silence exceeds the configured timeout, the session closes with timeout.

## Security Properties

The current handshake family is ML-KEM-based and post-quantum focused.

Session payloads are encrypted and authenticated. The session header stays visible so the receiver can route the record, but it is still authenticated as AEAD AAD.

QLv2 also provides forward secrecy in the following sense: even if an attacker later obtains a peer's long-term ML-KEM private key, they still cannot decrypt messages from earlier completed sessions.
