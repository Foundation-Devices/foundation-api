use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_channel::{Receiver, Sender};
use bc_components::{
    Digest, MLDSAPrivateKey, MLDSAPublicKey, MLKEMPrivateKey, MLKEMPublicKey, SymmetricKey, MLDSA,
    MLKEM, XID,
};
use rkyv::{Archive, Serialize};
use tokio::task::LocalSet;

use crate::{
    platform::{PlatformFuture, QlCrypto, QlPlatform},
    runtime::{
        new_runtime, HandlerEvent, KeepAliveConfig, PeerSession, RuntimeConfig, RuntimeHandle,
    },
    wire::{
        self, handshake::HandshakeRecord, heartbeat::HeartbeatBody, now_secs, pair,
        AsWireMlKemCiphertext, AsWireNonce, AsWireXid, QlHeader, QlPayload, QlRecord,
    },
    MessageId, PacketId, Peer, QlError,
};

mod handshake;
mod heartbeat;
mod persistence;
mod rpc;
mod stream;
mod unpair;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerStage {
    Disconnected,
    Initiator,
    Responder,
    Connected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatusEvent {
    peer: XID,
    stage: PeerStage,
}

struct TestPlatform {
    signing_private: MLDSAPrivateKey,
    signing_public: MLDSAPublicKey,
    encapsulation_private: MLKEMPrivateKey,
    encapsulation_public: MLKEMPublicKey,
    outbound: Sender<Vec<u8>>,
    status: Sender<StatusEvent>,
    nonce_seed: u8,
    nonce_counter: AtomicU8,
    fail_on_write: Option<usize>,
    write_counter: AtomicUsize,
}

impl TestPlatform {
    fn new(seed: u8) -> (Self, Receiver<Vec<u8>>, Receiver<StatusEvent>) {
        Self::new_with_fail_on_write(seed, None)
    }

    fn new_with_failed_write(
        seed: u8,
        fail_on_write: usize,
    ) -> (Self, Receiver<Vec<u8>>, Receiver<StatusEvent>) {
        Self::new_with_fail_on_write(seed, Some(fail_on_write))
    }

    fn new_with_fail_on_write(
        seed: u8,
        fail_on_write: Option<usize>,
    ) -> (Self, Receiver<Vec<u8>>, Receiver<StatusEvent>) {
        let (signing_private, signing_public) = MLDSA::MLDSA44.keypair();
        let (encapsulation_private, encapsulation_public) = MLKEM::MLKEM512.keypair();
        let (outbound, outbound_rx) = async_channel::unbounded();
        let (status, status_rx) = async_channel::unbounded();
        (
            Self {
                signing_private,
                signing_public,
                encapsulation_private,
                encapsulation_public,
                outbound,
                status,
                nonce_seed: seed,
                nonce_counter: AtomicU8::new(0),
                fail_on_write,
                write_counter: AtomicUsize::new(0),
            },
            outbound_rx,
            status_rx,
        )
    }

    fn signing_public_key(&self) -> &MLDSAPublicKey {
        &self.signing_public
    }

    fn encapsulation_public_key(&self) -> &MLKEMPublicKey {
        &self.encapsulation_public
    }
}

impl QlCrypto for TestPlatform {
    fn signing_private_key(&self) -> &MLDSAPrivateKey {
        &self.signing_private
    }

    fn signing_public_key(&self) -> &MLDSAPublicKey {
        &self.signing_public
    }

    fn encapsulation_private_key(&self) -> &MLKEMPrivateKey {
        &self.encapsulation_private
    }

    fn encapsulation_public_key(&self) -> &MLKEMPublicKey {
        &self.encapsulation_public
    }

    fn fill_random_bytes(&self, data: &mut [u8]) {
        let value = self
            .nonce_seed
            .wrapping_add(self.nonce_counter.fetch_add(1, Ordering::Relaxed));
        data.fill(value);
    }
}

impl QlPlatform for TestPlatform {
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>> {
        let fail_on_write = self.fail_on_write;
        let write_index = self.write_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let outbound = self.outbound.clone();
        Box::pin(async move {
            if fail_on_write == Some(write_index) {
                return Err(QlError::SendFailed);
            }
            outbound
                .send(message)
                .await
                .map_err(|_| QlError::InvalidPayload)
        })
    }

    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn load_peer(&self) -> PlatformFuture<'_, Option<Peer>> {
        Box::pin(async { None })
    }

    fn persist_peer(&self, _peer: Peer) {}

    fn clear_peer(&self) {}

    fn handle_peer_status(&self, peer: XID, session: &PeerSession) {
        let stage = match session {
            PeerSession::Disconnected => PeerStage::Disconnected,
            PeerSession::Initiator { .. } => PeerStage::Initiator,
            PeerSession::Responder { .. } => PeerStage::Responder,
            PeerSession::Connected { .. } => PeerStage::Connected,
        };
        let _ = self.status.try_send(StatusEvent { peer, stage });
    }

    fn handle_inbound(&self, _event: HandlerEvent) {}
}

struct InboundPlatform {
    signing_private: MLDSAPrivateKey,
    signing_public: MLDSAPublicKey,
    encapsulation_private: MLKEMPrivateKey,
    encapsulation_public: MLKEMPublicKey,
    outbound: Sender<Vec<u8>>,
    status: Sender<StatusEvent>,
    inbound: Sender<HandlerEvent>,
    nonce_seed: u8,
    nonce_counter: AtomicU8,
}

impl InboundPlatform {
    fn new(
        seed: u8,
    ) -> (
        Self,
        Receiver<Vec<u8>>,
        Receiver<StatusEvent>,
        Receiver<HandlerEvent>,
    ) {
        let (signing_private, signing_public) = MLDSA::MLDSA44.keypair();
        let (encapsulation_private, encapsulation_public) = MLKEM::MLKEM512.keypair();
        let (outbound, outbound_rx) = async_channel::unbounded();
        let (status, status_rx) = async_channel::unbounded();
        let (inbound, inbound_rx) = async_channel::unbounded();
        (
            Self {
                signing_private,
                signing_public,
                encapsulation_private,
                encapsulation_public,
                outbound,
                status,
                inbound,
                nonce_seed: seed,
                nonce_counter: AtomicU8::new(0),
            },
            outbound_rx,
            status_rx,
            inbound_rx,
        )
    }
}

impl QlCrypto for InboundPlatform {
    fn signing_private_key(&self) -> &MLDSAPrivateKey {
        &self.signing_private
    }

    fn signing_public_key(&self) -> &MLDSAPublicKey {
        &self.signing_public
    }

    fn encapsulation_private_key(&self) -> &MLKEMPrivateKey {
        &self.encapsulation_private
    }

    fn encapsulation_public_key(&self) -> &MLKEMPublicKey {
        &self.encapsulation_public
    }

    fn fill_random_bytes(&self, data: &mut [u8]) {
        let value = self
            .nonce_seed
            .wrapping_add(self.nonce_counter.fetch_add(1, Ordering::Relaxed));
        data.fill(value);
    }
}

impl QlPlatform for InboundPlatform {
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>> {
        let outbound = self.outbound.clone();
        Box::pin(async move {
            outbound
                .send(message)
                .await
                .map_err(|_| QlError::InvalidPayload)
        })
    }

    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn load_peer(&self) -> PlatformFuture<'_, Option<Peer>> {
        Box::pin(async { None })
    }

    fn persist_peer(&self, _peer: Peer) {}

    fn clear_peer(&self) {}

    fn handle_peer_status(&self, peer: XID, session: &PeerSession) {
        let stage = match session {
            PeerSession::Disconnected => PeerStage::Disconnected,
            PeerSession::Initiator { .. } => PeerStage::Initiator,
            PeerSession::Responder { .. } => PeerStage::Responder,
            PeerSession::Connected { .. } => PeerStage::Connected,
        };
        let _ = self.status.try_send(StatusEvent { peer, stage });
    }

    fn handle_inbound(&self, event: HandlerEvent) {
        let _ = self.inbound.try_send(event);
    }
}

async fn run_local_test<F>(future: F)
where
    F: Future<Output = ()>,
{
    let local = LocalSet::new();
    local.run_until(future).await;
}

fn spawn_forwarder(outbound: Receiver<Vec<u8>>, handle: RuntimeHandle) {
    tokio::task::spawn_local(async move {
        while let Ok(bytes) = outbound.recv().await {
            handle.send_incoming(bytes);
        }
    });
}

fn is_stream(bytes: &[u8]) -> bool {
    let Ok(record) = wire::decode_record(bytes) else {
        return false;
    };
    matches!(record.payload, QlPayload::Stream(_))
}

fn is_heartbeat(bytes: &[u8]) -> bool {
    let Ok(record) = wire::decode_record(bytes) else {
        return false;
    };
    matches!(record.payload, QlPayload::Heartbeat(_))
}

fn spawn_drop_first_stream_forwarder(outbound: Receiver<Vec<u8>>, handle: RuntimeHandle) {
    tokio::task::spawn_local(async move {
        let mut dropped = false;
        while let Ok(bytes) = outbound.recv().await {
            if !dropped && is_stream(&bytes) {
                dropped = true;
                continue;
            }
            handle.send_incoming(bytes);
        }
    });
}

fn spawn_drop_first_stream_when(
    outbound: Receiver<Vec<u8>>,
    handle: RuntimeHandle,
    armed: Arc<AtomicBool>,
) {
    tokio::task::spawn_local(async move {
        let mut dropped = false;
        while let Ok(bytes) = outbound.recv().await {
            if armed.load(Ordering::Relaxed) && !dropped && is_stream(&bytes) {
                dropped = true;
                continue;
            }
            handle.send_incoming(bytes);
        }
    });
}

fn spawn_duplicate_first_stream_forwarder(outbound: Receiver<Vec<u8>>, handle: RuntimeHandle) {
    tokio::task::spawn_local(async move {
        let mut duplicated = false;
        while let Ok(bytes) = outbound.recv().await {
            if !duplicated && is_stream(&bytes) {
                duplicated = true;
                handle.send_incoming(bytes.clone());
            }
            handle.send_incoming(bytes);
        }
    });
}

#[derive(Clone)]
struct SessionKeyMaterial {
    initiator_encapsulation_private: MLKEMPrivateKey,
    responder_encapsulation_private: MLKEMPrivateKey,
}

fn session_key_material(
    initiator: &TestPlatform,
    responder: &InboundPlatform,
) -> SessionKeyMaterial {
    SessionKeyMaterial {
        initiator_encapsulation_private: initiator.encapsulation_private.clone(),
        responder_encapsulation_private: responder.encapsulation_private.clone(),
    }
}

#[derive(Default)]
struct SessionTrace {
    hello_header: Option<QlHeader>,
    hello: Option<wire::handshake::Hello>,
    reply: Option<wire::handshake::HelloReply>,
    session_key: Option<SymmetricKey>,
}

#[derive(Archive, Serialize)]
struct TestHandshakeTranscript {
    #[rkyv(with = AsWireXid)]
    initiator: XID,
    #[rkyv(with = AsWireXid)]
    responder: XID,
    #[rkyv(with = AsWireNonce)]
    initiator_nonce: bc_components::Nonce,
    #[rkyv(with = AsWireNonce)]
    responder_nonce: bc_components::Nonce,
    #[rkyv(with = AsWireMlKemCiphertext)]
    initiator_kem_ct: bc_components::MLKEMCiphertext,
    #[rkyv(with = AsWireMlKemCiphertext)]
    responder_kem_ct: bc_components::MLKEMCiphertext,
}

#[derive(Archive, Serialize)]
struct TestSessionKeyMaterial {
    initiator_secret: Vec<u8>,
    responder_secret: Vec<u8>,
    transcript: Vec<u8>,
}

fn derive_session_key(
    trace: &SessionTrace,
    key_material: &SessionKeyMaterial,
) -> Option<SymmetricKey> {
    let header = trace.hello_header.as_ref()?;
    let hello = trace.hello.as_ref()?;
    let reply = trace.reply.as_ref()?;
    let initiator_secret = key_material
        .responder_encapsulation_private
        .decapsulate_shared_secret(&hello.kem_ct)
        .ok()?;
    let responder_secret = key_material
        .initiator_encapsulation_private
        .decapsulate_shared_secret(&reply.kem_ct)
        .ok()?;
    let transcript = wire::encode_value(&TestHandshakeTranscript {
        initiator: header.sender,
        responder: header.recipient,
        initiator_nonce: hello.nonce.clone(),
        responder_nonce: reply.nonce.clone(),
        initiator_kem_ct: hello.kem_ct.clone(),
        responder_kem_ct: reply.kem_ct.clone(),
    });
    let payload = wire::encode_value(&TestSessionKeyMaterial {
        initiator_secret: initiator_secret.as_bytes().to_vec(),
        responder_secret: responder_secret.as_bytes().to_vec(),
        transcript,
    });
    let digest = Digest::from_image(payload);
    Some(SymmetricKey::from_data(*digest.data()))
}

fn test_encryption_nonce(seed: u8) -> [u8; wire::encrypted_message::NONCE_SIZE] {
    [seed; wire::encrypted_message::NONCE_SIZE]
}

fn spawn_stream_mutating_forwarder<F>(
    outbound: Receiver<Vec<u8>>,
    handle: RuntimeHandle,
    key_material: SessionKeyMaterial,
    trace: Arc<Mutex<SessionTrace>>,
    mutator: F,
) where
    F: FnMut(&QlHeader, &mut wire::stream::StreamBody) -> bool + 'static,
{
    tokio::task::spawn_local(async move {
        let mut mutator = mutator;
        while let Ok(bytes) = outbound.recv().await {
            let Ok(record) = wire::access_record(&bytes) else {
                handle.send_incoming(bytes);
                continue;
            };

            {
                let mut trace = trace.lock().unwrap();
                match &record.payload {
                    wire::ArchivedQlPayload::Handshake(
                        wire::handshake::ArchivedHandshakeRecord::Hello(hello),
                    ) => {
                        trace.hello_header = Some(wire::deserialize_value(&record.header).unwrap());
                        trace.hello = Some(wire::deserialize_value(hello).unwrap());
                    }
                    wire::ArchivedQlPayload::Handshake(
                        wire::handshake::ArchivedHandshakeRecord::HelloReply(reply),
                    ) => {
                        trace.reply = Some(wire::deserialize_value(reply).unwrap());
                    }
                    _ => {}
                }
                if trace.session_key.is_none() {
                    trace.session_key = derive_session_key(&trace, &key_material);
                }
            }

            let session_key = trace.lock().unwrap().session_key.clone();
            if let (Some(session_key), wire::ArchivedQlPayload::Stream(encrypted)) =
                (session_key, &record.payload)
            {
                let header = wire::deserialize_value(&record.header).unwrap();
                let encrypted = wire::deserialize_value(encrypted).unwrap();
                let plaintext = encrypted.decrypt(&session_key, &header.aad());
                if let Ok(plaintext) = plaintext {
                    let body = wire::access_value::<wire::stream::ArchivedStreamBody>(&plaintext)
                        .and_then(wire::deserialize_value);
                    if let Ok(mut body) = body {
                        if mutator(&header, &mut body) {
                            let mutated = wire::stream::encrypt_stream(
                                header,
                                &session_key,
                                body.clone(),
                                test_encryption_nonce(body.packet_id.0 as u8),
                            );
                            handle.send_incoming(wire::encode_record(&mutated));
                            continue;
                        }
                    }
                }
            }

            handle.send_incoming(bytes);
        }
    });
}

fn spawn_drop_every_nth_stream_forwarder(
    outbound: Receiver<Vec<u8>>,
    handle: RuntimeHandle,
    nth: usize,
) {
    tokio::task::spawn_local(async move {
        let mut stream_count = 0usize;
        while let Ok(bytes) = outbound.recv().await {
            if nth > 0 && is_stream(&bytes) {
                stream_count = stream_count.saturating_add(1);
                if stream_count % nth == 0 {
                    continue;
                }
            }
            handle.send_incoming(bytes);
        }
    });
}

fn spawn_heartbeat_tap_forwarder(
    outbound: Receiver<Vec<u8>>,
    handle: RuntimeHandle,
    heartbeat_tx: Sender<()>,
) {
    tokio::task::spawn_local(async move {
        while let Ok(bytes) = outbound.recv().await {
            if is_heartbeat(&bytes) {
                let _ = heartbeat_tx.send(()).await;
            }
            handle.send_incoming(bytes);
        }
    });
}

fn spawn_drop_heartbeat_forwarder(outbound: Receiver<Vec<u8>>, handle: RuntimeHandle) {
    tokio::task::spawn_local(async move {
        while let Ok(bytes) = outbound.recv().await {
            if is_heartbeat(&bytes) {
                continue;
            }
            handle.send_incoming(bytes);
        }
    });
}

fn spawn_gated_forwarder(
    outbound: Receiver<Vec<u8>>,
    handle: RuntimeHandle,
    drop_flag: Arc<AtomicBool>,
) {
    tokio::task::spawn_local(async move {
        while let Ok(bytes) = outbound.recv().await {
            if drop_flag.load(Ordering::Relaxed) {
                continue;
            }
            handle.send_incoming(bytes);
        }
    });
}

#[derive(Clone)]
struct PeerIdentity {
    xid: XID,
    signing_key: MLDSAPublicKey,
    encapsulation_key: MLKEMPublicKey,
}

fn peer_identity(platform: &impl QlCrypto) -> PeerIdentity {
    PeerIdentity {
        xid: platform.xid(),
        signing_key: platform.signing_public_key().clone(),
        encapsulation_key: platform.encapsulation_public_key().clone(),
    }
}

fn register_peers(
    handle_a: &RuntimeHandle,
    handle_b: &RuntimeHandle,
    identity_a: &PeerIdentity,
    identity_b: &PeerIdentity,
) {
    handle_a.bind_peer(Peer {
        peer: identity_b.xid,
        signing_key: identity_b.signing_key.clone(),
        encapsulation_key: identity_b.encapsulation_key.clone(),
    });
    handle_b.bind_peer(Peer {
        peer: identity_a.xid,
        signing_key: identity_a.signing_key.clone(),
        encapsulation_key: identity_a.encapsulation_key.clone(),
    });
}

type PersistPlatformParts = (
    PersistPlatform,
    Receiver<Vec<u8>>,
    Receiver<StatusEvent>,
    Receiver<Option<crate::Peer>>,
);

struct PersistPlatform {
    signing_private: MLDSAPrivateKey,
    signing_public: MLDSAPublicKey,
    encapsulation_private: MLKEMPrivateKey,
    encapsulation_public: MLKEMPublicKey,
    outbound: Sender<Vec<u8>>,
    status: Sender<StatusEvent>,
    persisted: Sender<Option<crate::Peer>>,
    loaded_peer: Option<crate::Peer>,
    nonce_seed: u8,
    nonce_counter: AtomicU8,
}

impl PersistPlatform {
    fn new(seed: u8, loaded_peer: Option<crate::Peer>) -> PersistPlatformParts {
        let (signing_private, signing_public) = MLDSA::MLDSA44.keypair();
        let (encapsulation_private, encapsulation_public) = MLKEM::MLKEM512.keypair();
        let (outbound, outbound_rx) = async_channel::unbounded();
        let (status, status_rx) = async_channel::unbounded();
        let (persisted, persisted_rx) = async_channel::unbounded();
        (
            Self {
                signing_private,
                signing_public,
                encapsulation_private,
                encapsulation_public,
                outbound,
                status,
                persisted,
                loaded_peer,
                nonce_seed: seed,
                nonce_counter: AtomicU8::new(0),
            },
            outbound_rx,
            status_rx,
            persisted_rx,
        )
    }
}

impl QlCrypto for PersistPlatform {
    fn signing_private_key(&self) -> &MLDSAPrivateKey {
        &self.signing_private
    }
    fn signing_public_key(&self) -> &MLDSAPublicKey {
        &self.signing_public
    }
    fn encapsulation_private_key(&self) -> &MLKEMPrivateKey {
        &self.encapsulation_private
    }
    fn encapsulation_public_key(&self) -> &MLKEMPublicKey {
        &self.encapsulation_public
    }

    fn fill_random_bytes(&self, data: &mut [u8]) {
        let value = self
            .nonce_seed
            .wrapping_add(self.nonce_counter.fetch_add(1, Ordering::Relaxed));
        data.fill(value);
    }
}

impl QlPlatform for PersistPlatform {
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>> {
        let outbound = self.outbound.clone();
        Box::pin(async move {
            outbound
                .send(message)
                .await
                .map_err(|_| QlError::InvalidPayload)
        })
    }

    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn load_peer(&self) -> PlatformFuture<'_, Option<crate::Peer>> {
        let peer = self.loaded_peer.clone();
        Box::pin(async move { peer })
    }

    fn persist_peer(&self, peer: crate::Peer) {
        let _ = self.persisted.try_send(Some(peer));
    }

    fn clear_peer(&self) {
        let _ = self.persisted.try_send(None);
    }

    fn handle_peer_status(&self, peer: XID, session: &PeerSession) {
        let stage = match session {
            PeerSession::Disconnected => PeerStage::Disconnected,
            PeerSession::Initiator { .. } => PeerStage::Initiator,
            PeerSession::Responder { .. } => PeerStage::Responder,
            PeerSession::Connected { .. } => PeerStage::Connected,
        };
        let _ = self.status.try_send(StatusEvent { peer, stage });
    }

    fn handle_inbound(&self, _event: HandlerEvent) {}
}

async fn await_status(
    receiver: &Receiver<StatusEvent>,
    peer: XID,
    stage: PeerStage,
) -> StatusEvent {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(event) = receiver.recv().await {
                if event.peer == peer && event.stage == stage {
                    return event;
                }
            }
        }
    })
    .await
    .unwrap()
}

#[test]
fn protocol_record_size_breakdown() {
    let (platform_a, _outbound_a, _status_a) = TestPlatform::new(1);
    let (platform_b, _outbound_b, _status_b) = TestPlatform::new(2);

    let initiator = platform_a.xid();
    let responder = platform_b.xid();

    let (hello, initiator_secret) = wire::handshake::build_hello(
        &platform_a,
        initiator,
        responder,
        platform_b.encapsulation_public_key(),
    )
    .unwrap();
    let hello_record = QlRecord {
        header: QlHeader {
            sender: initiator,
            recipient: responder,
        },
        payload: QlPayload::Handshake(HandshakeRecord::Hello(hello.clone())),
    };
    let hello_size = wire::encode_record(&hello_record).len();
    let hello_bytes = wire::encode_value(&hello);
    let hello_view = wire::access_value::<wire::handshake::ArchivedHello>(&hello_bytes).unwrap();

    let (hello_reply, responder_secrets) = wire::handshake::respond_hello(
        &platform_b,
        initiator,
        responder,
        platform_a.encapsulation_public_key(),
        hello_view,
    )
    .unwrap();
    let reply_record = QlRecord {
        header: QlHeader {
            sender: responder,
            recipient: initiator,
        },
        payload: QlPayload::Handshake(HandshakeRecord::HelloReply(hello_reply.clone())),
    };
    let reply_size = wire::encode_record(&reply_record).len();
    let reply_bytes = wire::encode_value(&hello_reply);
    let reply_view =
        wire::access_value::<wire::handshake::ArchivedHelloReply>(&reply_bytes).unwrap();

    let (confirm, session_key) = wire::handshake::build_confirm(
        &platform_a,
        initiator,
        responder,
        platform_b.signing_public_key(),
        &hello,
        reply_view,
        &initiator_secret,
    )
    .unwrap();
    let confirm_bytes = wire::encode_value(&confirm);
    let confirm_view =
        wire::access_value::<wire::handshake::ArchivedConfirm>(&confirm_bytes).unwrap();
    let confirm_record = QlRecord {
        header: QlHeader {
            sender: initiator,
            recipient: responder,
        },
        payload: QlPayload::Handshake(HandshakeRecord::Confirm(confirm.clone())),
    };
    let confirm_size = wire::encode_record(&confirm_record).len();
    let _session_key_b = wire::handshake::finalize_confirm(
        initiator,
        responder,
        platform_a.signing_public_key(),
        &hello,
        &hello_reply,
        confirm_view,
        &responder_secrets,
    )
    .unwrap();

    let pair_size = wire::encode_record(
        &pair::build_pair_request(
            &platform_a,
            responder,
            platform_b.encapsulation_public_key(),
            MessageId(11),
            Duration::from_secs(60),
        )
        .unwrap(),
    )
    .len();

    let heartbeat_size = wire::encode_record(&wire::heartbeat::encrypt_heartbeat(
        QlHeader {
            sender: initiator,
            recipient: responder,
        },
        &session_key,
        HeartbeatBody {
            message_id: MessageId(12),
            valid_until: wire::now_secs().saturating_add(60),
        },
        test_encryption_nonce(12),
    ))
    .len();

    let unpair_size = wire::encode_record(&wire::unpair::build_unpair_record(
        &platform_a,
        QlHeader {
            sender: initiator,
            recipient: responder,
        },
        MessageId(13),
        wire::now_secs().saturating_add(60),
    ))
    .len();

    let stream_record_size =
        |packet_id: PacketId,
         packet_ack: Option<wire::stream::PacketAck>,
         frame: Option<wire::stream::StreamFrame>| {
            wire::encode_record(&wire::stream::encrypt_stream(
                QlHeader {
                    sender: initiator,
                    recipient: responder,
                },
                &session_key,
                wire::stream::StreamBody {
                    packet_id,
                    valid_until: wire::now_secs().saturating_add(60),
                    packet_ack,
                    frame,
                },
                test_encryption_nonce(packet_id.0 as u8),
            ))
            .len()
        };

    let stream_header = QlHeader {
        sender: initiator,
        recipient: responder,
    };
    let stream_ack_body = wire::stream::StreamBody {
        packet_id: PacketId(20),
        valid_until: wire::now_secs().saturating_add(60),
        packet_ack: Some(wire::stream::PacketAck {
            packet_id: PacketId(19),
        }),
        frame: None,
    };
    let stream_ack_record = wire::stream::encrypt_stream(
        stream_header.clone(),
        &session_key,
        stream_ack_body.clone(),
        test_encryption_nonce(20),
    );
    let stream_ack_encrypted = match &stream_ack_record.payload {
        QlPayload::Stream(encrypted) => encrypted,
        _ => unreachable!(),
    };
    let stream_ack_header_size = wire::encode_value(&stream_header).len();
    let stream_ack_body_size = wire::encode_value(&stream_ack_body).len();
    let stream_ack_envelope_size = wire::encode_value(stream_ack_encrypted).len();
    let stream_ack_payload_size = wire::encode_value(&stream_ack_record.payload).len();

    let stream_open_body = wire::stream::StreamBody {
        packet_id: PacketId(21),
        valid_until: wire::now_secs().saturating_add(60),
        packet_ack: None,
        frame: Some(wire::stream::StreamFrame::Open(
            wire::stream::StreamFrameOpen {
                stream_id: crate::StreamId(2),
                request_head: vec![1, 2, 3],
                response_max_offset: 1024,
            },
        )),
    };
    let stream_open_body_size = wire::encode_value(&stream_open_body).len();

    let stream_ack_size = stream_record_size(
        PacketId(20),
        Some(wire::stream::PacketAck {
            packet_id: PacketId(19),
        }),
        None,
    );
    let stream_open_size = stream_record_size(
        PacketId(21),
        None,
        Some(wire::stream::StreamFrame::Open(
            wire::stream::StreamFrameOpen {
                stream_id: crate::StreamId(2),
                request_head: vec![1, 2, 3],
                response_max_offset: 1024,
            },
        )),
    );
    let stream_accept_size = stream_record_size(
        PacketId(22),
        None,
        Some(wire::stream::StreamFrame::Accept(
            wire::stream::StreamFrameAccept {
                stream_id: crate::StreamId(2),
                response_head: vec![4, 5, 6],
                request_max_offset: 2048,
            },
        )),
    );
    let stream_reject_size = stream_record_size(
        PacketId(23),
        None,
        Some(wire::stream::StreamFrame::Reject(
            wire::stream::StreamFrameReject {
                stream_id: crate::StreamId(2),
                code: wire::stream::RejectCode::InvalidHead,
            },
        )),
    );
    let stream_data_size = stream_record_size(
        PacketId(24),
        None,
        Some(wire::stream::StreamFrame::Data(
            wire::stream::StreamFrameData {
                stream_id: crate::StreamId(2),
                dir: wire::stream::Direction::Request,
                offset: 128,
                bytes: vec![7, 8, 9, 10],
            },
        )),
    );
    let stream_credit_size = stream_record_size(
        PacketId(25),
        None,
        Some(wire::stream::StreamFrame::Credit(
            wire::stream::StreamFrameCredit {
                stream_id: crate::StreamId(2),
                dir: wire::stream::Direction::Response,
                recv_offset: 256,
                max_offset: 4096,
            },
        )),
    );
    let stream_finish_size = stream_record_size(
        PacketId(26),
        None,
        Some(wire::stream::StreamFrame::Finish(
            wire::stream::StreamFrameFinish {
                stream_id: crate::StreamId(2),
                dir: wire::stream::Direction::Response,
            },
        )),
    );
    let stream_reset_size = stream_record_size(
        PacketId(27),
        None,
        Some(wire::stream::StreamFrame::Reset(
            wire::stream::StreamFrameReset {
                stream_id: crate::StreamId(2),
                dir: wire::stream::ResetTarget::Both,
                code: wire::stream::ResetCode::Protocol,
            },
        )),
    );

    let print_size = |label: &str, size: usize| {
        println!("{label:<23}: {size} bytes");
    };

    print_size("ql2 size hello", hello_size);
    print_size("ql2 size hello_reply", reply_size);
    print_size("ql2 size confirm", confirm_size);
    print_size("ql2 size pair", pair_size);
    print_size("ql2 size heartbeat", heartbeat_size);
    print_size("ql2 size unpair", unpair_size);
    print_size("ql2 size stream ack", stream_ack_size);
    print_size("ql2 size stream open", stream_open_size);
    print_size("ql2 size stream accept", stream_accept_size);
    print_size("ql2 size stream reject", stream_reject_size);
    print_size("ql2 size stream data", stream_data_size);
    print_size("ql2 size stream credit", stream_credit_size);
    print_size("ql2 size stream finish", stream_finish_size);
    print_size("ql2 size stream reset", stream_reset_size);
    println!(
        "ql2 stream ack breakdown : header={} derived_aad={} plaintext={} ciphertext={} envelope(no aad)={} payload={} full={}",
        stream_ack_header_size,
        stream_header.aad().len(),
        stream_ack_body_size,
        stream_ack_body_size,
        stream_ack_envelope_size,
        stream_ack_payload_size,
        stream_ack_size,
    );
    println!(
        "ql2 stream open delta    : open_body={} ack_body={} (+{} request_head bytes)",
        stream_open_body_size,
        stream_ack_body_size,
        stream_open_body_size.saturating_sub(stream_ack_body_size),
    );
}
