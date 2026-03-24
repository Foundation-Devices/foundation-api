# QuantumLink V2 Design Document

QuantumLink V2 is a peer-to-peer protocol for authenticated, encrypted sessions carrying multiplexed byte streams.

It replaces QLv1's one-message-at-a-time model with explicit pairing, handshake, session, and stream state.

QLv2 operates on complete QL records and leaves transport-specific framing, fragmentation, reassembly, and delivery behavior to platform adapters.

## Table of contents
- [Design goals](#design-goals)
- [Non-design goals](#non-design-goals)
- [Protocol model](#protocol-model)
- [Session handshake](#handshake)
- [Session sequencing and reliability](#session-sequencing-and-reliability)
- [Keepalive and liveness](#keepalive-and-liveness)
- [Stream model](#stream-model)

## Design goals
1. [use ephemeral peer sessions for record encryption](#1-explicit-peer-sessions)
2. [include a minimal unencrypted but authenticated header](#2-minimal-authenticated-header)
3. [keep the record layer transport-agnostic](#3-transport-agnostic-record-layer)
4. [add QL-level reliability above the transport](#4-ql-level-reliability)
5. [use duplex byte streams as the application primitive](#5-duplex-byte-streams)
6. [efficient protocol wire format](#6-efficient-wire-format)
7. [provide a single shared protocol state machine across platforms](#7-shared-core-state-machine)
8. [support hardware-backed cryptography](#8-hardware-backed-cryptography)

### 1. Explicit peer sessions
QLv2 replaces per-exchange sealing with explicit pairing, handshake, session, and stream state. This keeps peer state durable across many records, amortizes large post-quantum signatures and expensive key exchange, and keeps steady-state traffic smaller and cheaper.

### 2. Minimal authenticated header
QLv2 keeps a small header visible on the wire while still authenticating it. This lets a host route a record to the correct local or third-party application before decryption without exposing more metadata than necessary.

The visible record header currently includes:

- protocol version
- record kind
- sender XID
- recipient XID

This header is intentionally narrow, and can be extended in the future if needed.

### 3. Transport-agnostic record layer
The core protocol only consumes and produces complete QL records. Framing, batching, fragmentation, and reassembly stay in the transport adapter so the same protocol can run over transports such as TCP, BLE, or L2CAP without rewriting core logic.

### 4. QL-level reliability
QLv2 includes QL-level sequence numbers and acknowledgments above the transport. A transport can usually only tell us that bytes were accepted for transmission. A QL acknowledgment tells us something stronger: the peer received and decrypted the message with the session key.

This is deliberate redundancy, not a replacement for transport reliability. It is not sufficient for a fully unreliable transport like raw UDP, but it does make QLv2 more robust on transports that should be reliable in theory yet have shown implementation-level flakiness in practice, such as Passport Prime's embedded BLE.

### 5. Duplex byte streams
QLv2 treats duplex byte streams as the application primitive rather than building in a separate model for each interaction style. Request/response, subscriptions, progress updates, and bulk transfer can all be adapted to the same abstraction, which also gives useful behavior such as finish semantics, cancellation, and backpressure without separate protocol features.

### 6. Efficient wire format
The wire format should stay compact, cheap to process, and independent of any one implementation language. QLv2 uses an efficient binary encoding with explicit endianness and fixed layouts, so records can be parsed consistently across platforms.

The record sizes shows the protocol's intended split between setup and steady-state traffic. Setup records are relatively large because they carry post-quantum cryptography material, while steady-state session records are much smaller.

| Record type | Encoded size |
| --- | ---: |
| `hello` | 6253 bytes |
| `hello_reply` | 6253 bytes |
| `confirm` | 4673 bytes |
| `pair_request empty` | 1630 bytes |
| `unpair` | 4673 bytes |
| `ready empty` | 62 bytes |
| `session ack` | 87 bytes |
| `session ping` | 87 bytes |
| `session stream empty` | 100 bytes |
| `session stream fin` | 100 bytes |
| `session stream close` | 94 bytes |
| `session close` | 89 bytes |

### 7. Shared core state machine
QLv2 should have one core implementation of pairing, handshake, session, retransmission, and stream behavior. Platforms should integrate that shared state machine instead of rebuilding subtle protocol logic independently.

### 8. Hardware-backed cryptography
QLv2 separates parts of its cryptographic implementation through the `QlCrypto` trait. Each platform can provide its own source of randomness, hashing, and AEAD encryption and decryption, choosing software or hardware-backed implementations as appropriate.

```rust
pub trait QlCrypto {
    fn fill_random_bytes(&self, data: &mut [u8]);
    fn hash(&self, parts: &[&[u8]]) -> [u8; 32];
    fn encrypt_with_aead(&self, /*...*/) -> [u8; EncryptedMessage::AUTH_SIZE];
    fn decrypt_with_aead(&self, /*...*/) -> bool;
}
```

## Non-design goals
- not a replacement for TCP, QUIC, BLE, or any other transport
- not a universal reliability layer for arbitrary raw packets
- not responsible for framing, batching, fragmentation, or reassembly on a given platform
- not responsible for how QL records map onto TCP reads/writes, BLE packets, or similar transport units
- not a general-purpose message bus above the stream layer
- not an attempt to preserve QLv1's sealed-message model in the core protocol

## Protocol model
QLv2 has four layers of state:

- `Pairing` establish a durable peer relationship
- `Handshake` establish a fresh encrypted session between paired peers
- `Session` carries authenticated encrypted traffic with QL-level acknowledgment and retransmission
- `Stream` multiplex many concurrent duplex byte streams inside one session

`Unpair` is a peer-level signed control record outside the session. It tears down the pairing relationship on a best-effort basis and does not depend on session ordering or session establishment.

This structure gives QLv2 a few important properties:

- one peer relationship can span many sessions over time
- one session can carry many streams at once
- stream data from different streams can be interwoven on the same session
- ordering is preserved within a stream, not across all streams
- one blocked stream does not block unrelated streams

## Handshake
The handshake authenticates both peers, derives a fresh session key, and confirms that both sides can use it.

| Message | Sender | Est. size | Purpose |
| --- | --- | ---: | --- |
| `hello` | initiator | ~6253 bytes | start the handshake, contribute fresh key material, prove initiator identity |
| `hello_reply` | responder | ~6253 bytes | contribute fresh key material, prove responder identity, bind to `hello` |
| `confirm` | initiator | ~4673 bytes | prove the initiator saw `hello_reply` and derived the same session |
| `ready` | responder | ~62 bytes | prove the responder derived the session key by encrypting under it |

Both peers contribute fresh key material during the handshake. The signatures bind the exchange to the two peers and to the full handshake transcript rather than to isolated messages. The session key is derived from the combined exchange. `ready` is the final key confirmation step because it is encrypted under that new session key.

The handshake also follows a few simple rules:

- each handshake message has a bounded lifetime
- duplicate handshake messages can trigger resend of the matching response
- simultaneous `hello` messages are resolved deterministically so only one side continues as the initiator

## Session sequencing and reliability
This layer gives the session record-level acknowledgment and retransmission, independent of any one stream.

| Term | Meaning |
| --- | --- |
| `seq` | session-wide sequence number for one encrypted record |
| `ack.base` | all sequence numbers up to this point are acknowledged |
| `ack.bitmap` | selective acknowledgment for the next 64 sequence numbers after `ack.base` |

- every encrypted session record gets a `seq`
- the sequence space is shared by all streams on the session
- receivers can acknowledge out-of-order records within the session receive window
- retransmission resends the same logical session record with the same `seq`
- a QL acknowledgment tells us that the peer received the record, decrypted it successfully under the current session key, verified it, and accepted its session sequence number

### Keepalive and liveness
- when a session is idle, a peer may send a `ping` to show that the session is still alive
- the peer does not answer with another `ping`; it simply acknowledges the record at the normal session layer
- if inbound traffic stays silent for too long, the session is treated as dead and closed

Multiple streams can be interwoven in the same session. A missing session record can stall byte delivery on its own stream, but it does not block unrelated streams.

## Stream model
QLv2 uses duplex byte streams as the application primitive.

- each stream has independent inbound and outbound directions
- either peer can open a stream at any time
- many streams can be active on the same session
- bytes are delivered in order within a stream
- each stream chunk may carry bytes and may also mark that direction as complete
- this supports both bounded exchanges and long-lived streams

Normal completion means one side is done sending bytes on that direction while the other direction may continue. Explicit close is different. It terminates one side or both sides of the stream early and carries a close code.

By convention, higher-level protocols can treat one direction as a request and the other as a response.

### Example: RPC over streams

#### Unary request/response

- the caller opens a stream
- the caller writes the request bytes and marks the request direction complete
- the responder reads the request, writes the response bytes, and marks the response direction complete

#### Subscription

- the caller opens a stream and writes a request body (any subscription parameters)
- the caller marks the request direction complete once the request is sent
- the responder keeps writing response updates on the response direction until the subscription ends or the job completes
- either side can explicitly close the stream early to cancel
