# QuantumLink V2 Design Document

QuantumLink V2 is a peer-to-peer protocol for authenticated encrypted sessions carrying multiplexed duplex byte streams.

It operates on whole QL records. Packetization, fragmentation, batching, and reassembly belong to the transport adapter, not to QLv2 itself.

The handshake is the setup phase. It authenticates the remote peer, establishes a fresh session, and derives the keys used for steady-state traffic.

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
- `XID`: a stable 16-byte peer identifier
- `peer bundle`: public peer information: `version`, `xid`, `capabilities`, and ML-KEM public key
- `session`: one live encrypted channel with directional keys and directional connection IDs
- `record`: one complete QLv2 wire unit
- `frame`: one logical item inside a session record
- `stream`: one duplex byte stream inside a session
- `stream origin`: the peer that opened the stream
- `origin lane`: bytes sent by the stream origin
- `return lane`: bytes sent back toward the stream origin

## Record And Frame Wire Format

QLv2 has two record types:

- `handshake record`: used only during setup
- `session record`: used after the handshake completes

Handshake records are large because they carry ML-KEM material. Session records are small and can carry multiple frames, including frames for different streams.

Handshake records are routed by peer identity. Session records are routed by `connection_id`.

### Handshake records

| Record | Size | Used when | Purpose |
| --- | ---: | --- | --- |
| `IK1` | 4793 bytes | initiator already knows the responder bundle | start a handshake toward a known responder |
| `IK2` | 3203 bytes | second message of `IK` | finish the responder side of the handshake and establish the session |
| `KK1` | 3187 bytes | both peers already know each other | start a handshake between already-known peers |
| `KK2` | 3203 bytes | second message of `KK` | finish the responder side of the handshake and establish the session |

### Session records

`session record size = 42 + sum(frame sizes)`

There is no explicit AEAD nonce on the wire. The record `seq` is used to derive the nonce.

| Fixed part | Size | Purpose |
| --- | ---: | --- |
| version | 1 byte | protocol version |
| record type | 1 byte | identifies a session record |
| `connection_id` | 16 bytes | route the record to the current session |
| `seq` | 8 bytes | record identity for ack and retransmit |
| AEAD auth tag | 16 bytes | authenticate the encrypted body |
| fixed overhead total | 42 bytes | overhead before any frames |

The visible session header is authenticated as AEAD AAD but is not encrypted.

### Session frames

| Frame | Size | Purpose |
| --- | ---: | --- |
| `Ping` | 1 byte | keep the session alive when idle |
| `Ack` | 17 bytes | acknowledge received session records |
| `StreamWindow` | 13 bytes | extend per-stream send credit |
| `StreamClose` | 10 bytes | abort one stream lane or both lanes |
| `Close` | 3 bytes | close the whole session |
| `StreamData` | `16 + payload_len` bytes | carry stream bytes and optional `fin` |

`StreamData` is the main steady-state frame:

`1 kind + 2 variable-length prefix + 4 stream_id + 8 offset + 1 fin + payload_len`

Some useful minimum record sizes:

| Record | Size | Meaning |
| --- | ---: | --- |
| `Ping` only | 43 bytes | idle keepalive |
| `Close` only | 45 bytes | session shutdown |
| empty or fin-only `StreamData` | 58 bytes | open or finish a stream lane without payload bytes |

## Handshake

QLv2 currently supports two 2-message Noise-style handshake patterns:

- `IK`: the initiator already knows the responder bundle
- `KK`: both peers already know each other

The handshake covers peer authentication and session establishment. There is no separate peer-level pairing record.

The handshake does five things:

1. authenticate which peer we are talking to
2. derive a fresh transmit key and receive key
3. derive a directional transmit `connection_id` and receive `connection_id`
4. bind transport parameters into the transcript
5. produce a `handshake_hash` for the completed exchange

Today, first-contact identity exchange is still partly out of band. `IK` removes the need for the responder to know the initiator in advance, but the initiator still needs the responder bundle before it can start. A future pattern such as `XX` could remove that requirement.

Each handshake carries:

- `handshake_id`: identifies one handshake attempt
- `valid_until`: expiration time for that attempt
- transport parameters: today this is initial per-stream receive credit

Important behavior:

- handshake start messages are replay-checked by `handshake_id`
- expired handshake messages are rejected
- simultaneous starts are resolved deterministically
- handshake attempts time out and are dropped rather than being retransmitted in place

Session establishment is slightly asymmetric:

- the responder enters the connected state when it processes message 1 and constructs message 2
- the initiator enters the connected state when it receives message 2

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

Retransmission works at the frame level:

- every emitted session record gets a fresh `seq`
- retransmit timers start only after the local transport confirms that it accepted the write
- if a record is considered lost, the FSM restores its frames
- those frames are packed into a new record with a new `seq`

QLv2 does not resend the same logical record identity.

Receivers track a recent record window so they can:
- reject duplicates
- send selective acks with `base_seq + bitmap`

## Streams

Streams are the application primitive.

A stream has two independent lanes:

- origin lane
- return lane

Important properties:

- either peer can open a stream
- stream IDs are split by parity so both peers can open streams without collision
- ordering is preserved within a stream lane
- different streams can make progress independently
- record loss on one stream does not block unrelated streams

`StreamData` carries:

- `stream_id`
- `offset`
- `fin`
- bytes

`fin` is graceful completion of one lane. It says "no more bytes on this lane" without aborting the other lane.

## Flow Control

Flow control is per stream.

During the handshake, each peer advertises an initial per-stream receive window. That becomes the initial send credit the remote peer can use on each stream.

`StreamWindow` extends that credit by advertising a larger maximum offset.

Important detail: reading bytes is not what returns credit. Committing those reads is what returns credit and causes window updates to be sent.

In practice, a stream is writable only when both are true:

- local send buffering has room
- peer-advertised stream credit allows more bytes

## Close And Liveness

`StreamClose` aborts a stream early. Semantically it can target:

- the origin lane
- the return lane
- both lanes

`Close` aborts the whole session.

Idle sessions may send `Ping`. The peer does not answer with another ping; normal record acknowledgment is enough.

Sessions also have local timers for:

- handshake timeout
- delayed ack emission
- session record retransmit timeout
- keepalive ping interval
- peer silence timeout

## Security Properties

The current handshake is ML-KEM-based and post-quantum focused.

Session payloads are encrypted and authenticated. The session header stays visible so the receiver can route the record, but it is still authenticated as AEAD AAD.

QLv2 also provides forward secrecy in the following sense: even if an attacker later obtains a peer's long-term ML-KEM private key, they still cannot decrypt messages from earlier completed sessions.

