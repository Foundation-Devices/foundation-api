# QuantumLink V2 Design Document

  QuantumLink V2 is a peer-to-peer protocol for authenticated, encrypted sessions carrying multiplexed byte streams.

  It replaces QLv1's one-message-at-a-time model with explicit pairing, handshake, session, and stream state.

  QLv2 operates on complete QL records and leaves transport-specific framing, fragmentation, reassembly, and delivery behavior to platform adapters.

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

### 3. Transport-agnostic record layer
The core protocol only consumes and produces complete QL records. Framing, batching, fragmentation, and reassembly stay in the transport adapter so the same protocol can run over transports such as TCP, BLE, or L2CAP without rewriting core logic.

### 4. QL-level reliability
QLv2 includes QL-level sequence numbers and acknowledgments above the transport. A transport can usually only tell us that bytes were accepted for transmission. A QL acknowledgment tells us something stronger: the peer received, decrypted, and authenticated the record with the current session key.

This is deliberate redundancy, not a replacement for transport reliability. It is not sufficient for a fully unreliable transport like raw UDP, but it does make QLv2 more robust on transports that should be reliable in theory yet have shown implementation-level flakiness in practice, such as Passport Prime's embedded BLE.

### 5. Duplex byte streams
QLv2 treats duplex byte streams as the application primitive rather than building in a separate model for each interaction style. Request/response, subscriptions, progress updates, and bulk transfer can all be adapted to the same abstraction, which also gives useful behavior such as finish semantics, cancellation, and backpressure without separate protocol features.

### 6. Efficient wire format
The wire format should stay compact, cheap to process, and independent of any one implementation language. QLv2 uses an efficient binary encoding with explicit endianness and fixed layouts, so records can be parsed consistently across platforms and can support zero-copy or near-zero-copy implementations where appropriate.

The record sizes shows the protocol's intended split between setup and steady-state traffic. Setup records are relatively large because they carry post-quantum material, while steady-state session records are much smaller.

| Record type | Encoded size |
| --- | ---: |
| `hello` | 6253 bytes |
| `hello_reply` | 6253 bytes |
| `confirm` | 4673 bytes |
| `pair_request empty` | 1630 bytes |
| `ready empty` | 62 bytes |
| `session ack` | 87 bytes |
| `session ping` | 87 bytes |
| `session unpair` | 87 bytes |
| `session stream empty` | 100 bytes |
| `session stream fin` | 100 bytes |
| `session stream close` | 94 bytes |
| `session close` | 89 bytes |

### 7. Shared core state machine
QLv2 should have one core implementation of pairing, handshake, session, retransmission, and stream behavior. Platforms should integrate that shared state machine instead of rebuilding subtle protocol logic independently.

### 8. Hardware-backed cryptography
QLv2 separates parts of its cryptographic implementation through the `QlCrypto` trait. Each platform can provide its own source of randomness, hashing, and AEAD encryption and decryption, choosing software or hardware-backed implementations as appropriate.

## Non-design goals
- not a replacement for TCP, QUIC, BLE, or any other transport
- not a universal reliability layer for arbitrary raw packets
- not responsible for framing, batching, fragmentation, or reassembly on a given platform
- not responsible for how QL records map onto TCP reads/writes, BLE packets, or similar transport units
- not a general-purpose message bus above the stream layer
- not an attempt to preserve QLv1's sealed-message model in the core protocol
