use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

use async_channel::{Receiver, Sender};
use bc_components::{
    MLDSA, MLDSAPrivateKey, MLDSAPublicKey, MLKEM, MLKEMPrivateKey, MLKEMPublicKey, XID,
};
use dcbor::CBOR;
use tokio::{sync::Semaphore, task::LocalSet};

use crate::{
    crypto::{
        handshake as crypto_handshake, heartbeat as crypto_heartbeat,
        message::encrypt_message, pair,
    },
    platform::{PlatformFuture, QlPlatform, QlPlatformExt},
    runtime::{
        internal::now_secs, new_runtime, HandlerEvent, KeepAliveConfig, PeerSession, RequestConfig,
        RuntimeConfig, RuntimeHandle,
    },
    wire::{
        handshake::HandshakeRecord,
        heartbeat::HeartbeatBody,
        message::{MessageBody, MessageKind, Nack},
        QlHeader, QlPayload, QlRecord,
    },
    MessageId, QlError, RouteId,
};

mod handshake;
mod requests;
mod heartbeat;

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

    fn fill_bytes(&self, data: &mut [u8]) {
        let value = self
       fill_random_bytese_seed
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

    fn handle_peer_status(&self, peer: XID, session: &PeerSession) {
        let stage = match session {
            PeerSession::Disconnected => PeerStage::Disconnected,
            PeerSession::Initiator { .. } => PeerStage::Initiator,
            PeerSession::Responder { .. } => PeerStage::Responder,
            PeerSession::Connected { .. } => PeerStage::Connected,
        };
        let _ = self.status.try_send(StatusEvent { peer, stage });
    }

    fn handle_inbound(&self, _event: crate::runtime::HandlerEvent) {}
}

struct BlockingPlatform {
    signing_private: MLDSAPrivateKey,
    signing_public: MLDSAPublicKey,
    encapsulation_private: MLKEMPrivateKey,
    encapsulation_public: MLKEMPublicKey,
    outbound: Sender<Vec<u8>>,
    status: Sender<StatusEvent>,
    nonce_seed: u8,
    nonce_counter: AtomicU8,
    write_gate: Arc<Semaphore>,
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

    fn fill_bytes(&self, data: &mut [u8]) {
        let value = self
            .nonce_seed
       fill_random_bytesping_add(self.nonce_counter.fetch_add(1, Ordering::Relaxed));
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

impl BlockingPlatform {
    fn new(
        seed: u8,
    ) -> (
        Self,
        Receiver<Vec<u8>>,
        Receiver<StatusEvent>,
        Arc<Semaphore>,
    ) {
        let (signing_private, signing_public) = MLDSA::MLDSA44.keypair();
        let (encapsulation_private, encapsulation_public) = MLKEM::MLKEM512.keypair();
        let (outbound, outbound_rx) = async_channel::unbounded();
        let (status, status_rx) = async_channel::unbounded();
        let write_gate = Arc::new(Semaphore::new(0));
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
                write_gate: write_gate.clone(),
            },
            outbound_rx,
            status_rx,
            write_gate,
        )
    }
}

impl QlPlatform for BlockingPlatform {
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

    fn fill_bytes(&self, data: &mut [u8]) {
        let value = self
            .nonce_seed
            .wrapping_add(self.nonce_counter.fetch_add(1, Ordering::Relaxed));
       fill_random_bytes(value);
    }

    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>> {
        let outbound = self.outbound.clone();
        let write_gate = self.write_gate.clone();
        Box::pin(async move {
            let _permit = write_gate.acquire().await.unwrap();
            outbound
                .send(message)
                .await
                .map_err(|_| QlError::InvalidPayload)
        })
    }

    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
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

    fn handle_inbound(&self, _event: crate::runtime::HandlerEvent) {}
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
            let _ = handle.send_incoming(bytes);
        }
    });
}

fn is_heartbeat(bytes: &[u8]) -> bool {
    let Ok(record) = CBOR::try_from_data(bytes).and_then(QlRecord::try_from) else {
        return false;
    };
    matches!(record.payload, QlPayload::Heartbeat(_))
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
            let _ = handle.send_incoming(bytes);
        }
    });
}

fn spawn_drop_heartbeat_forwarder(outbound: Receiver<Vec<u8>>, handle: RuntimeHandle) {
    tokio::task::spawn_local(async move {
        while let Ok(bytes) = outbound.recv().await {
            if is_heartbeat(&bytes) {
                continue;
            }
            let _ = handle.send_incoming(bytes);
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
            let _ = handle.send_incoming(bytes);
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
                let _ = handle.send_incoming(bytes);
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
) -> (XID, XID) {
    let peer_a = identity_a.xid;
    let peer_b = identity_b.xid;
    handle_a.register_peer(
        peer_b,
        identity_b.signing_key.clone(),
        identity_b.encapsulation_key.clone(),
    );
    handle_b.register_peer(
        peer_a,
        identity_a.signing_key.clone(),
        identity_a.encapsulation_key.clone(),
    );
    (peer_a, peer_b)
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

    let (hello, initiator_secret) = crypto_handshake::build_hello(
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

    let (hello_reply, responder_secrets) = crypto_handshake::respond_hello(
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

    let (confirm, session_key) = crypto_handshake::build_confirm(
        &platform_a,
        initiator,
        responder,
        platform_b.signing_public_key(),
        &hello,
        &hello_reply,
        &initiator_secret,
    )
    .unwrap();
    let _session_key_b = crypto_handshake::finalize_confirm(
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

    let pair_record = pair::build_pair_request(
        &platform_a,
        responder,
        platform_b.encapsulation_public_key(),
        MessageId::new(1),
        Duration::from_secs(60),
    )
    .unwrap();
    let pair_size = CBOR::from(pair_record).to_cbor_data().len();

    let message_record = encrypt_message(
        QlHeader {
            sender: initiator,
            recipient: responder,
        },
        &session_key,
        MessageBody {
            message_id: MessageId::new(2),
            valid_until: now_secs().saturating_add(60),
            kind: MessageKind::Event,
            route_id: RouteId::new(1),
            payload: CBOR::null(),
        },
    );
    let message_size = CBOR::from(message_record).to_cbor_data().len();

    let heartbeat_record = crypto_heartbeat::encrypt_heartbeat(
        QlHeader {
            sender: initiator,
            recipient: responder,
        },
        &session_key,
        HeartbeatBody {
            message_id: MessageId::new(3),
            valid_until: now_secs().saturating_add(60),
        },
    );
    let heartbeat_size = CBOR::from(heartbeat_record).to_cbor_data().len();

    let print_size = |label: &str, size: usize| {
        println!("{:<21}: {} bytes", label, size);
    };

    print_size("ql size hello", hello_size);
    print_size("ql size hello_reply", reply_size);
    print_size("ql size confirm", confirm_size);
    print_size("ql size pair_request", pair_size);
    print_size("ql size message", message_size);
    print_size("ql size heartbeat", heartbeat_size);
}
