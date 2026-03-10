use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_channel::{Receiver, Sender};
use bc_components::{
    Digest, MLDSAPrivateKey, MLDSAPublicKey, MLKEMPrivateKey, MLKEMPublicKey, MLDSA, MLKEM,
    SymmetricKey, XID,
};
use dcbor::CBOR;
use tokio::task::LocalSet;

use crate::{
    platform::{PlatformFuture, QlPlatform, QlPlatformExt},
    runtime::{
        internal::now_secs, new_runtime, HandlerEvent, KeepAliveConfig, PeerSession, RuntimeConfig,
        RuntimeHandle,
    },
    wire::{
        self, handshake::HandshakeRecord, heartbeat::HeartbeatBody, pair, QlHeader, QlPayload,
        QlRecord,
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
}

impl TestPlatform {
    fn new(seed: u8) -> (Self, Receiver<Vec<u8>>, Receiver<StatusEvent>) {
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

impl QlPlatform for TestPlatform {
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

    fn load_peers(&self) -> PlatformFuture<'_, Vec<Peer>> {
        Box::pin(async { Vec::new() })
    }

    fn persist_peers(&self, _peers: Vec<Peer>) {}

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

impl QlPlatform for InboundPlatform {
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

    fn load_peers(&self) -> PlatformFuture<'_, Vec<Peer>> {
        Box::pin(async { Vec::new() })
    }

    fn persist_peers(&self, _peers: Vec<Peer>) {}

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
    let Ok(record) = CBOR::try_from_data(bytes).and_then(QlRecord::try_from) else {
        return false;
    };
    matches!(record.payload, QlPayload::Stream(_))
}

fn is_heartbeat(bytes: &[u8]) -> bool {
    let Ok(record) = CBOR::try_from_data(bytes).and_then(QlRecord::try_from) else {
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
    let transcript = CBOR::from(vec![
        CBOR::from(header.sender),
        CBOR::from(header.recipient),
        CBOR::from(hello.nonce.clone()),
        CBOR::from(reply.nonce.clone()),
        CBOR::from(hello.kem_ct.clone()),
        CBOR::from(reply.kem_ct.clone()),
    ])
    .to_cbor_data();
    let payload = CBOR::from(vec![
        CBOR::from(initiator_secret.as_bytes()),
        CBOR::from(responder_secret.as_bytes()),
        CBOR::from(transcript),
    ])
    .to_cbor_data();
    let digest = Digest::from_image(payload);
    Some(SymmetricKey::from_data(*digest.data()))
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
            let Ok(record) = CBOR::try_from_data(&bytes).and_then(QlRecord::try_from) else {
                handle.send_incoming(bytes);
                continue;
            };

            {
                let mut trace = trace.lock().unwrap();
                match &record.payload {
                    QlPayload::Handshake(HandshakeRecord::Hello(hello)) => {
                        trace.hello_header = Some(record.header.clone());
                        trace.hello = Some(hello.clone());
                    }
                    QlPayload::Handshake(HandshakeRecord::HelloReply(reply)) => {
                        trace.reply = Some(reply.clone());
                    }
                    _ => {}
                }
                if trace.session_key.is_none() {
                    trace.session_key = derive_session_key(&trace, &key_material);
                }
            }

            let session_key = trace.lock().unwrap().session_key.clone();
            if let (Some(session_key), QlPayload::Stream(encrypted)) = (session_key, &record.payload) {
                if let Ok(mut body) = wire::stream::decrypt_stream(&record.header, encrypted, &session_key) {
                    if mutator(&record.header, &mut body) {
                        let mutated = wire::stream::encrypt_stream(record.header, &session_key, body);
                        handle.send_incoming(CBOR::from(mutated).to_cbor_data());
                        continue;
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

fn spawn_routed_forwarder(outbound: Receiver<Vec<u8>>, routes: Vec<(XID, RuntimeHandle)>) {
    spawn_routed_forwarder_with_filter(outbound, routes, |_| true);
}

fn spawn_routed_forwarder_with_filter<F>(
    outbound: Receiver<Vec<u8>>,
    routes: Vec<(XID, RuntimeHandle)>,
    filter: F,
) where
    F: Fn(&QlRecord) -> bool + Send + Sync + 'static,
{
    tokio::task::spawn_local(async move {
        while let Ok(bytes) = outbound.recv().await {
            let Ok(record) = CBOR::try_from_data(&bytes).and_then(QlRecord::try_from) else {
                continue;
            };
            if !filter(&record) {
                continue;
            }
            if let Some((_, handle)) = routes
                .iter()
                .find(|(peer, _)| *peer == record.header.recipient)
            {
                handle.send_incoming(bytes);
            }
        }
    });
}

#[derive(Clone)]
struct PeerIdentity {
    xid: XID,
    signing_key: MLDSAPublicKey,
    encapsulation_key: MLKEMPublicKey,
}

fn peer_identity(platform: &impl QlPlatformExt) -> PeerIdentity {
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
    handle_a.register_peer(
        identity_b.xid,
        identity_b.signing_key.clone(),
        identity_b.encapsulation_key.clone(),
    );
    handle_b.register_peer(
        identity_a.xid,
        identity_a.signing_key.clone(),
        identity_a.encapsulation_key.clone(),
    );
}

type PersistPlatformParts = (
    PersistPlatform,
    Receiver<Vec<u8>>,
    Receiver<StatusEvent>,
    Receiver<Vec<crate::Peer>>,
);

struct PersistPlatform {
    signing_private: MLDSAPrivateKey,
    signing_public: MLDSAPublicKey,
    encapsulation_private: MLKEMPrivateKey,
    encapsulation_public: MLKEMPublicKey,
    outbound: Sender<Vec<u8>>,
    status: Sender<StatusEvent>,
    persisted: Sender<Vec<crate::Peer>>,
    loaded_peers: Vec<crate::Peer>,
    nonce_seed: u8,
    nonce_counter: AtomicU8,
}

impl PersistPlatform {
    fn new(seed: u8, loaded_peers: Vec<crate::Peer>) -> PersistPlatformParts {
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
                loaded_peers,
                nonce_seed: seed,
                nonce_counter: AtomicU8::new(0),
            },
            outbound_rx,
            status_rx,
            persisted_rx,
        )
    }
}

impl QlPlatform for PersistPlatform {
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

    fn load_peers(&self) -> PlatformFuture<'_, Vec<crate::Peer>> {
        let peers = self.loaded_peers.clone();
        Box::pin(async move { peers })
    }

    fn persist_peers(&self, peers: Vec<crate::Peer>) {
        let _ = self.persisted.try_send(peers);
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
    let hello_size = CBOR::from(hello_record).to_cbor_data().len();

    let (hello_reply, responder_secrets) = wire::handshake::respond_hello(
        &platform_b,
        initiator,
        responder,
        platform_a.encapsulation_public_key(),
        &hello,
    )
    .unwrap();
    let reply_record = QlRecord {
        header: QlHeader {
            sender: responder,
            recipient: initiator,
        },
        payload: QlPayload::Handshake(HandshakeRecord::HelloReply(hello_reply.clone())),
    };
    let reply_size = CBOR::from(reply_record).to_cbor_data().len();

    let (confirm, session_key) = wire::handshake::build_confirm(
        &platform_a,
        initiator,
        responder,
        platform_b.signing_public_key(),
        &hello,
        &hello_reply,
        &initiator_secret,
    )
    .unwrap();
    let _session_key_b = wire::handshake::finalize_confirm(
        initiator,
        responder,
        platform_a.signing_public_key(),
        &hello,
        &hello_reply,
        &confirm,
        &responder_secrets,
    )
    .unwrap();
    let confirm_record = QlRecord {
        header: QlHeader {
            sender: initiator,
            recipient: responder,
        },
        payload: QlPayload::Handshake(HandshakeRecord::Confirm(confirm)),
    };
    let confirm_size = CBOR::from(confirm_record).to_cbor_data().len();

    let stream_record = wire::stream::encrypt_stream(
        QlHeader {
            sender: initiator,
            recipient: responder,
        },
        &session_key,
        wire::stream::StreamBody {
            packet_id: PacketId(1),
            valid_until: wire::now_secs().saturating_add(60),
            packet_ack: None,
            frame: Some(wire::stream::StreamFrame::Open(
                wire::stream::StreamFrameOpen {
                    stream_id: crate::StreamId(2),
                    request_head: vec![1, 2, 3],
                    response_max_offset: 1024,
                },
            )),
        },
    );
    let stream_size = CBOR::from(stream_record).to_cbor_data().len();

    let print_size = |label: &str, size: usize| {
        println!("{label:<21}: {size} bytes");
    };

    print_size("ql2 size hello", hello_size);
    print_size("ql2 size hello_reply", reply_size);
    print_size("ql2 size confirm", confirm_size);
    print_size("ql2 size stream open", stream_size);
    let _ = MessageId(0);
}
