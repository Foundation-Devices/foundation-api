# QuantumLink V2

QLV2 is designed around the shortcomings of QLV1.

QLV1 worked, but it treated each message too much like a standalone encrypted blob. That made routing hard, pairing clunky, repeated messages expensive, reliability awkward, and application encoding too baked into the protocol.

QLV2 moves QuantumLink toward authenticated encrypted sessions with reliable duplex byte streams.

## Problems And Solutions

### The protocol assumed specific product roles

**Problem:** QLV1 was effectively shaped around the Prime/Envoy relationship. It was not a generic protocol for arbitrary peers; the wire model and pairing flow assumed who the participants were and what direction the relationship moved in.

**Solution:** QLV2 models peers generically. A peer has a `PeerBundle` representing its public identity, including its QID, independent of whether it is Passport, Envoy, KeyOS, a mobile app, or something else.

### Messages were not routable

**Problem:** QLV1 messages were not cheaply introspectable. A peer or transport adapter could not look at a message and know where it was supposed to go.

**Solution:** QLV2 records have public, but verified, routing headers. Known-peer records expose sender and recipient QIDs, and session records expose enough metadata to route them to the right session.

This lets a single connection, like BLE, multiplex different senders and recipients on both ends. For example, iPhone/Android can have multiple apps using the same BLE connection, while KeyOS can still know which sender produced a record and which destination app should receive it.

This also opens the door to QL-level packet forwarding, because peers can cheaply inspect a record and forward it to the right destination without needing to understand or decrypt the payload.

### Encryption overhead was too high

**Problem:** The minimum payload size for a QLV1 message is about 6.6KB.

**Solution:** QLV2 amortizes the KEM and encryption setup cost into a session. Handshake messages are still large, but steady-state message overhead drops to roughly `35..42` bytes, depending on varint encoding size.

### Key compromise could expose old messages

**Problem:** QLV1 had no built-in key rotation model. If a long-term key was compromised, old messages were at risk.

**Solution:** QLV2 uses Noise-style session handshakes so every session gets unique encryption keys. Compromising one session does not automatically compromise future sessions.

### Reliability lived above the protocol

**Problem:** QLV1 was fundamentally unreliable, so reliability had to be rebuilt by each higher-level API. Any message flow that needed dependable delivery had to invent its own retry/reliability behavior in userspace.

**Solution:** QLV2 is built around reliable streams. One session can carry many duplex byte streams, and reliability is solved once at the QL layer instead of repeatedly in user/application space.

### Encoding was baked into the protocol

**Problem:** QLV1 was tied to a specific CBOR codec, even when the protocol did not really need that. This added serialization/deserialization cost and extra memory pressure.

**Solution:** QLV2 uses binary framing internally and exposes byte streams to user space. Since QL is fundamentally moving bytes, the implementation can use zero-copy byte views where possible instead of copying payloads through a serialization layer. Applications can still layer whatever encoding they want on top: JSON, CBOR, XML, or something else. That choice belongs above QL.

### RPC patterns had to be reinvented per API

**Problem:** QLV1 mixed protocol transport with application workflow shape. If a feature needed request/response behavior, progress updates, downloads, uploads, or subscriptions, that behavior had to be manually modeled in its message types. The protocol did not provide reusable workflow primitives, so every feature had to encode its own control flow.

**Solution:** QLV2 makes reliable byte streams the primitive. `ql-rpc` sits above QLV2 and gives those streams common RPC modalities: request/response, notification, upload, download, subscription, and duplex. QL stays focused on peer identity, session establishment, encryption, routing, and reliable byte transport.

### Pairing lived in userspace

**Problem:** QLV1 did not treat peer establishment as a protocol concern. Pairing had to be implemented as an application message flow, which made it directional, informal, and hard to generalize beyond the original Prime/Envoy convention.

**Solution:** QLV2 lifts peer establishment into the protocol. Pairing becomes one protocol-supported way to establish a session, not a one-off userspace convention.

QLV2 has different session establishment modalities for different starting states:

- `XX`: first-time pairing using a small out-of-band `PairingToken`
- `IK`: the initiator already knows the responder
- `KK`: both peers already know each other
