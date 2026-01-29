use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_channel::{Receiver, Sender};
use bc_components::{
    Decrypter, EncapsulationPrivateKey, EncapsulationPublicKey, Signer, SigningPublicKey,
    SymmetricKey, XID,
};
use dcbor::CBOR;
use oneshot;

use crate::{
    identity::QlIdentity,
    router::{EventHandler, QlRequest, RequestHandler, Router},
    runtime::{
        PlatformFuture, QlPeer, QlPlatform, RequestConfig, ResetOrigin, Runtime, RuntimeConfig,
    },
    wire::{
        decode_ql_message, encode_ql_message, encrypt_pairing_request,
        encrypt_payload_for_recipient, MessageKind, Nack, QlHeader, QlMessage, QlPayload,
    },
    Event, QlError, RequestResponse,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ping(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pong(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Notice(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnknownRequest(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BadPing;

impl From<Ping> for CBOR {
    fn from(value: Ping) -> Self {
        CBOR::from(value.0)
    }
}

impl TryFrom<CBOR> for Ping {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let value: u64 = value.try_into()?;
        Ok(Self(value))
    }
}

impl From<Pong> for CBOR {
    fn from(value: Pong) -> Self {
        CBOR::from(value.0)
    }
}

impl TryFrom<CBOR> for Pong {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let value: u64 = value.try_into()?;
        Ok(Self(value))
    }
}

impl From<Notice> for CBOR {
    fn from(value: Notice) -> Self {
        CBOR::from(value.0)
    }
}

impl TryFrom<CBOR> for Notice {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let value: u64 = value.try_into()?;
        Ok(Self(value))
    }
}

impl From<UnknownRequest> for CBOR {
    fn from(value: UnknownRequest) -> Self {
        CBOR::from(value.0)
    }
}

impl TryFrom<CBOR> for UnknownRequest {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let value: u64 = value.try_into()?;
        Ok(Self(value))
    }
}

impl From<BadPing> for CBOR {
    fn from(_: BadPing) -> Self {
        CBOR::from("bad")
    }
}

impl TryFrom<CBOR> for BadPing {
    type Error = dcbor::Error;

    fn try_from(_: CBOR) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}

impl RequestResponse for Ping {
    const ID: u64 = 100;
    type Response = Pong;
}

impl RequestResponse for UnknownRequest {
    const ID: u64 = 101;
    type Response = Pong;
}

impl RequestResponse for BadPing {
    const ID: u64 = Ping::ID;
    type Response = Pong;
}

impl Event for Notice {
    const ID: u64 = 200;
}

#[derive(Clone)]
struct TestPlatform {
    inner: Arc<TestPlatformInner>,
}

struct TestPlatformInner {
    identity: QlIdentity,
    peer: Mutex<Option<Box<TestPeer>>>,
    tx: Sender<Vec<u8>>,
    errors: Mutex<Vec<QlError>>,
}

impl TestPlatform {
    fn new(
        identity: QlIdentity,
        peer: EncapsulationPublicKey,
        peer_signing_key: SigningPublicKey,
    ) -> (Self, Receiver<Vec<u8>>) {
        let (tx, rx) = async_channel::unbounded();
        let inner = TestPlatformInner {
            identity,
            peer: Mutex::new(Some(Box::new(TestPeer::new(peer, peer_signing_key)))),
            tx,
            errors: Mutex::new(Vec::new()),
        };
        (
            Self {
                inner: Arc::new(inner),
            },
            rx,
        )
    }

    fn new_unpaired(identity: QlIdentity) -> (Self, Receiver<Vec<u8>>) {
        let (tx, rx) = async_channel::unbounded();
        let inner = TestPlatformInner {
            identity,
            peer: Mutex::new(None),
            tx,
            errors: Mutex::new(Vec::new()),
        };
        (
            Self {
                inner: Arc::new(inner),
            },
            rx,
        )
    }

    fn pending_handshake(&self) -> Option<crate::runtime::PendingHandshake> {
        let guard = self.inner.peer.lock().ok()?;
        guard.as_ref()?.pending_handshake()
    }

    fn set_pending_handshake(&self, handshake: Option<crate::runtime::PendingHandshake>) {
        let Ok(guard) = self.inner.peer.lock() else {
            return;
        };
        let Some(peer) = guard.as_ref() else {
            return;
        };
        peer.set_pending_handshake(handshake);
    }

    fn take_errors(&self) -> Vec<QlError> {
        let Ok(mut guard) = self.inner.errors.lock() else {
            return Vec::new();
        };
        std::mem::take(&mut *guard)
    }
}

impl QlPlatform for TestPlatform {
    fn lookup_peer(&self, peer: XID) -> Option<&dyn QlPeer> {
        let guard = self.inner.peer.lock().ok()?;
        let stored = guard.as_ref()?;
        if peer != XID::new(&stored.signing_public_key) {
            return None;
        }
        let ptr = stored.as_ref() as *const TestPeer;
        Some(unsafe { &*ptr })
    }

    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey {
        self.inner.identity.private_keys.encapsulation_private_key()
    }

    fn encapsulation_public_key(&self) -> EncapsulationPublicKey {
        self.inner.identity.encapsulation_public_key.clone()
    }

    fn signing_key(&self) -> &SigningPublicKey {
        &self.inner.identity.signing_public_key
    }

    fn message_expiration(&self) -> Duration {
        Duration::from_secs(60)
    }

    fn signer(&self) -> &dyn Signer {
        &self.inner.identity.private_keys
    }

    fn handle_error(&self, e: QlError) {
        if let Ok(mut guard) = self.inner.errors.lock() {
            guard.push(e);
        }
    }

    fn store_peer(
        &self,
        signing_pub_key: SigningPublicKey,
        encapsulation_pub_key: EncapsulationPublicKey,
        session: SymmetricKey,
    ) -> Result<(), QlError> {
        let peer = Box::new(TestPeer::new(encapsulation_pub_key, signing_pub_key));
        peer.store_session(session);
        let mut guard = self.inner.peer.lock().map_err(|_| QlError::Cancelled)?;
        *guard = Some(peer);
        Ok(())
    }

    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>> {
        let tx = self.inner.tx.clone();
        Box::pin(async move { tx.send(message).await.map_err(|_| QlError::Cancelled) })
    }

    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

struct TestPeer {
    encapsulation_public_key: EncapsulationPublicKey,
    signing_public_key: SigningPublicKey,
    session: Mutex<Option<SymmetricKey>>,
    pending_handshake: Mutex<Option<crate::runtime::PendingHandshake>>,
}

impl TestPeer {
    fn new(
        encapsulation_public_key: EncapsulationPublicKey,
        signing_public_key: SigningPublicKey,
    ) -> Self {
        Self {
            encapsulation_public_key,
            signing_public_key,
            session: Mutex::new(None),
            pending_handshake: Mutex::new(None),
        }
    }
}

impl QlPeer for TestPeer {
    fn encapsulation_pub_key(&self) -> &EncapsulationPublicKey {
        &self.encapsulation_public_key
    }

    fn signing_pub_key(&self) -> &SigningPublicKey {
        &self.signing_public_key
    }

    fn session(&self) -> Option<SymmetricKey> {
        self.session.lock().unwrap().clone()
    }

    fn store_session(&self, key: SymmetricKey) {
        let mut guard = self.session.lock().unwrap();
        *guard = Some(key);
    }

    fn pending_handshake(&self) -> Option<crate::runtime::PendingHandshake> {
        *self.pending_handshake.lock().unwrap()
    }

    fn set_pending_handshake(&self, handshake: Option<crate::runtime::PendingHandshake>) {
        let mut guard = self.pending_handshake.lock().unwrap();
        *guard = handshake;
    }
}

struct TestState {
    event_tx: Option<oneshot::Sender<u64>>,
}

impl RequestHandler<Ping> for TestState {
    fn handle(&mut self, request: QlRequest<Ping>) {
        let response = Pong(request.message.0 + 1);
        let _ = request.responder.respond(response);
    }

    fn default_response() -> Pong {
        Pong(0)
    }
}

impl EventHandler<Notice> for TestState {
    fn handle(&mut self, event: Notice) {
        if let Some(tx) = self.event_tx.take() {
            let _ = tx.send(event.0);
        }
    }
}

fn build_reset_message(
    sender: &QlIdentity,
    recipient: &QlIdentity,
    id: bc_components::ARID,
) -> QlMessage {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let valid_until = now.saturating_add(60);
    let (session_key, kem_ct) = recipient
        .encapsulation_public_key
        .encapsulate_new_shared_secret();
    let header = QlHeader {
        kind: MessageKind::SessionReset,
        id,
        sender: sender.xid,
        recipient: recipient.xid,
        valid_until,
        kem_ct: Some(kem_ct.clone()),
        signature: None,
    };
    let signature = Some(
        sender
            .private_keys
            .sign(&header.aad_data())
            .expect("sign reset header"),
    );
    let header = QlHeader {
        signature,
        ..header
    };
    let aad = header.aad_data();
    let payload_bytes = CBOR::null().to_cbor_data();
    let encrypted = session_key.encrypt(payload_bytes, Some(aad), None::<bc_components::Nonce>);
    let bytes = encode_ql_message(header, encrypted);
    decode_ql_message(&bytes).expect("decode reset")
}

#[tokio::test(flavor = "current_thread")]
async fn typed_round_trip() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let client_identity = QlIdentity::generate();
            let server_identity = QlIdentity::generate();
            let (client_platform, client_outbound) = TestPlatform::new(
                client_identity.clone(),
                server_identity.encapsulation_public_key.clone(),
                server_identity.signing_public_key.clone(),
            );
            let (server_platform, server_outbound) = TestPlatform::new(
                server_identity.clone(),
                client_identity.encapsulation_public_key.clone(),
                client_identity.signing_public_key.clone(),
            );
            let config = RuntimeConfig {
                default_timeout: Duration::from_secs(1),
            };

            let (mut client_core, client_handle, _client_incoming) =
                Runtime::new(client_platform.clone(), config);
            let (mut server_core, server_handle, mut server_incoming) =
                Runtime::new(server_platform.clone(), config);

            tokio::task::spawn_local(async move { client_core.run().await });
            tokio::task::spawn_local(async move { server_core.run().await });

            tokio::task::spawn_local({
                let server_handle = server_handle.clone();
                async move {
                    while let Ok(bytes) = client_outbound.recv().await {
                        server_handle.send_incoming(bytes).unwrap();
                    }
                }
            });

            tokio::task::spawn_local({
                let client_handle = client_handle.clone();
                async move {
                    while let Ok(bytes) = server_outbound.recv().await {
                        client_handle.send_incoming(bytes).unwrap();
                    }
                }
            });

            let (event_tx, event_rx) = oneshot::channel();
            let router = Router::builder()
                .add_request_handler::<Ping>()
                .add_event_handler::<Notice>()
                .build(TestState {
                    event_tx: Some(event_tx),
                });

            tokio::task::spawn_local({
                let mut router = router;
                async move {
                    loop {
                        let event = match server_incoming.next().await {
                            Ok(event) => event,
                            Err(_) => break,
                        };
                        let _ = router.handle(event);
                    }
                }
            });

            let recipient = server_platform.xid();

            client_handle.send_event(Notice(7), recipient).unwrap();
            let event_value = event_rx.await.expect("event handled");
            assert_eq!(event_value, 7);

            let response = client_handle
                .request(Ping(41), recipient, RequestConfig::default())
                .await
                .expect("response");
            assert_eq!(response, Pong(42));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn event_with_ack_round_trip() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let client_identity = QlIdentity::generate();
            let server_identity = QlIdentity::generate();
            let (client_platform, client_outbound) = TestPlatform::new(
                client_identity.clone(),
                server_identity.encapsulation_public_key.clone(),
                server_identity.signing_public_key.clone(),
            );
            let (server_platform, server_outbound) = TestPlatform::new(
                server_identity.clone(),
                client_identity.encapsulation_public_key.clone(),
                client_identity.signing_public_key.clone(),
            );
            let config = RuntimeConfig {
                default_timeout: Duration::from_secs(1),
            };

            let (mut client_core, client_handle, _client_incoming) =
                Runtime::new(client_platform.clone(), config);
            let (mut server_core, server_handle, mut server_incoming) =
                Runtime::new(server_platform.clone(), config);

            tokio::task::spawn_local(async move { client_core.run().await });
            tokio::task::spawn_local(async move { server_core.run().await });

            tokio::task::spawn_local({
                let server_handle = server_handle.clone();
                async move {
                    while let Ok(bytes) = client_outbound.recv().await {
                        server_handle.send_incoming(bytes).unwrap();
                    }
                }
            });

            tokio::task::spawn_local({
                let client_handle = client_handle.clone();
                async move {
                    while let Ok(bytes) = server_outbound.recv().await {
                        client_handle.send_incoming(bytes).unwrap();
                    }
                }
            });

            let router = Router::builder()
                .add_event_handler::<Notice>()
                .build(TestState { event_tx: None });

            tokio::task::spawn_local({
                let mut router = router;
                async move {
                    loop {
                        let event = match server_incoming.next().await {
                            Ok(event) => event,
                            Err(_) => break,
                        };
                        let _ = router.handle(event);
                    }
                }
            });

            let recipient = server_platform.xid();
            client_handle
                .send_event_with_ack(Notice(99), recipient, RequestConfig::default())
                .await
                .expect("event ack");
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn nack_unknown_message_is_returned() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let client_identity = QlIdentity::generate();
            let server_identity = QlIdentity::generate();
            let (client_platform, client_outbound) = TestPlatform::new(
                client_identity.clone(),
                server_identity.encapsulation_public_key.clone(),
                server_identity.signing_public_key.clone(),
            );
            let (server_platform, server_outbound) = TestPlatform::new(
                server_identity.clone(),
                client_identity.encapsulation_public_key.clone(),
                client_identity.signing_public_key.clone(),
            );
            let config = RuntimeConfig {
                default_timeout: Duration::from_secs(1),
            };

            let (mut client_core, client_handle, _client_incoming) =
                Runtime::new(client_platform.clone(), config);
            let (mut server_core, server_handle, mut server_incoming) =
                Runtime::new(server_platform.clone(), config);

            tokio::task::spawn_local(async move { client_core.run().await });
            tokio::task::spawn_local(async move { server_core.run().await });

            tokio::task::spawn_local({
                let server_handle = server_handle.clone();
                async move {
                    while let Ok(bytes) = client_outbound.recv().await {
                        server_handle.send_incoming(bytes).unwrap();
                    }
                }
            });

            tokio::task::spawn_local({
                let client_handle = client_handle.clone();
                async move {
                    while let Ok(bytes) = server_outbound.recv().await {
                        client_handle.send_incoming(bytes).unwrap();
                    }
                }
            });

            let router = Router::builder()
                .add_request_handler::<Ping>()
                .build(TestState { event_tx: None });

            tokio::task::spawn_local({
                let mut router = router;
                async move {
                    loop {
                        let event = match server_incoming.next().await {
                            Ok(event) => event,
                            Err(_) => break,
                        };
                        let _ = router.handle(event);
                    }
                }
            });

            let recipient = server_platform.xid();
            let result = client_handle
                .request(UnknownRequest(11), recipient, RequestConfig::default())
                .await;

            assert!(matches!(
                result,
                Err(QlError::Nack(nack)) if nack == Nack::UnknownMessage
            ));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn nack_invalid_payload_is_returned() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let client_identity = QlIdentity::generate();
            let server_identity = QlIdentity::generate();
            let (client_platform, client_outbound) = TestPlatform::new(
                client_identity.clone(),
                server_identity.encapsulation_public_key.clone(),
                server_identity.signing_public_key.clone(),
            );
            let (server_platform, server_outbound) = TestPlatform::new(
                server_identity.clone(),
                client_identity.encapsulation_public_key.clone(),
                client_identity.signing_public_key.clone(),
            );
            let config = RuntimeConfig {
                default_timeout: Duration::from_secs(1),
            };

            let (mut client_core, client_handle, _client_incoming) =
                Runtime::new(client_platform.clone(), config);
            let (mut server_core, server_handle, mut server_incoming) =
                Runtime::new(server_platform.clone(), config);

            tokio::task::spawn_local(async move { client_core.run().await });
            tokio::task::spawn_local(async move { server_core.run().await });

            tokio::task::spawn_local({
                let server_handle = server_handle.clone();
                async move {
                    while let Ok(bytes) = client_outbound.recv().await {
                        server_handle.send_incoming(bytes).unwrap();
                    }
                }
            });

            tokio::task::spawn_local({
                let client_handle = client_handle.clone();
                async move {
                    while let Ok(bytes) = server_outbound.recv().await {
                        client_handle.send_incoming(bytes).unwrap();
                    }
                }
            });

            let router = Router::builder()
                .add_request_handler::<Ping>()
                .build(TestState { event_tx: None });

            tokio::task::spawn_local({
                let mut router = router;
                async move {
                    loop {
                        let event = match server_incoming.next().await {
                            Ok(event) => event,
                            Err(_) => break,
                        };
                        let _ = router.handle(event);
                    }
                }
            });

            let recipient = server_platform.xid();
            let result = client_handle
                .request(BadPing, recipient, RequestConfig::default())
                .await;

            assert!(matches!(
                result,
                Err(QlError::Nack(nack)) if nack == Nack::InvalidPayload
            ));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn expired_response_is_rejected() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let requester = QlIdentity::generate();
            let responder = QlIdentity::generate();
            let (platform, outbound_rx) = TestPlatform::new(
                requester.clone(),
                responder.encapsulation_public_key.clone(),
                responder.signing_public_key.clone(),
            );
            let config = RuntimeConfig {
                default_timeout: Duration::from_secs(2),
            };
            let (mut core, handle, _incoming) = Runtime::new(platform.clone(), config);
            tokio::task::spawn_local(async move { core.run().await });

            let recipient = XID::new(&responder.signing_public_key);
            let request_handle = handle.clone();
            let response_task = tokio::task::spawn_local(async move {
                request_handle
                    .request(Ping(5), recipient, RequestConfig::default())
                    .await
            });

            let outbound = outbound_rx.recv().await.expect("no outbound request");
            let outbound_message = decode_ql_message(&outbound).expect("decode outbound");

            let session_key = platform
                .lookup_peer(recipient)
                .expect("peer")
                .session()
                .expect("session");
            let header = QlHeader {
                kind: MessageKind::Response,
                id: outbound_message.header.id,
                sender: responder.xid,
                recipient: outbound_message.header.sender,
                valid_until: 0,
                kem_ct: None,
                signature: None,
            };
            let payload = CBOR::from(6);
            let encrypted = session_key.encrypt(
                payload.to_cbor_data(),
                Some(header.aad_data()),
                None::<bc_components::Nonce>,
            );
            let response_bytes = encode_ql_message(header, encrypted);
            handle.send_incoming(response_bytes).unwrap();

            let response = response_task.await.unwrap();
            assert!(matches!(response, Err(QlError::Expired)));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn reset_cancels_pending_request() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let client_identity = QlIdentity::generate();
            let server_identity = QlIdentity::generate();
            let (client_platform, client_outbound) = TestPlatform::new(
                client_identity.clone(),
                server_identity.encapsulation_public_key.clone(),
                server_identity.signing_public_key.clone(),
            );
            let config = RuntimeConfig {
                default_timeout: Duration::from_secs(1),
            };
            let (mut client_core, client_handle, _client_incoming) =
                Runtime::new(client_platform.clone(), config);
            tokio::task::spawn_local(async move { client_core.run().await });

            let recipient = XID::new(&server_identity.signing_public_key);
            let request_handle = client_handle.clone();
            let request_task = tokio::task::spawn_local(async move {
                request_handle
                    .request(Ping(123), recipient, RequestConfig::default())
                    .await
            });

            let _ = client_outbound.recv().await.expect("outbound request");

            let reset_message = build_reset_message(
                &server_identity,
                &client_identity,
                bc_components::ARID::new(),
            );
            let reset_bytes = encode_ql_message(reset_message.header, reset_message.payload);
            client_handle.send_incoming(reset_bytes).unwrap();

            let result = request_task.await.unwrap();
            match result {
                Err(QlError::SessionReset) => {}
                other => panic!("unexpected result: {other:?}"),
            }
        })
        .await;
}

#[test]
fn simultaneous_session_init_resolves() {
    fn build_event_message(
        platform: &TestPlatform,
        recipient: XID,
        notice: Notice,
        message_id: bc_components::ARID,
    ) -> (QlHeader, bc_components::EncryptedMessage) {
        let payload = QlPayload {
            message_id: Notice::ID,
            payload: notice.into(),
        };
        encrypt_payload_for_recipient(
            platform,
            recipient,
            MessageKind::Event,
            message_id,
            payload.into(),
        )
        .expect("encrypt event")
    }

    let client_identity = QlIdentity::generate();
    let server_identity = QlIdentity::generate();
    let (client_platform, _client_outbound) = TestPlatform::new(
        client_identity.clone(),
        server_identity.encapsulation_public_key.clone(),
        server_identity.signing_public_key.clone(),
    );
    let (server_platform, _server_outbound) = TestPlatform::new(
        server_identity.clone(),
        client_identity.encapsulation_public_key.clone(),
        client_identity.signing_public_key.clone(),
    );

    let (client_header, client_encrypted) = build_event_message(
        &client_platform,
        server_platform.xid(),
        Notice(1),
        bc_components::ARID::new(),
    );
    let (server_header, server_encrypted) = build_event_message(
        &server_platform,
        client_platform.xid(),
        Notice(2),
        bc_components::ARID::new(),
    );

    let server_result =
        crate::wire::extract_payload(&server_platform, &client_header, client_encrypted);
    let client_result =
        crate::wire::extract_payload(&client_platform, &server_header, server_encrypted);

    if client_platform.xid() < server_platform.xid() {
        assert!(matches!(client_result, Err(QlError::SessionInitCollision)));
        assert!(server_result.is_ok());
    } else {
        assert!(matches!(server_result, Err(QlError::SessionInitCollision)));
        assert!(client_result.is_ok());
    }

    let (follow_up_client_header, follow_up_client_encrypted) = build_event_message(
        &client_platform,
        server_platform.xid(),
        Notice(3),
        bc_components::ARID::new(),
    );
    let (follow_up_server_header, follow_up_server_encrypted) = build_event_message(
        &server_platform,
        client_platform.xid(),
        Notice(4),
        bc_components::ARID::new(),
    );

    assert!(crate::wire::extract_payload(
        &server_platform,
        &follow_up_client_header,
        follow_up_client_encrypted
    )
    .is_ok());
    assert!(crate::wire::extract_payload(
        &client_platform,
        &follow_up_server_header,
        follow_up_server_encrypted
    )
    .is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn pairing_request_stores_peer() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let sender_identity = QlIdentity::generate();
            let recipient_identity = QlIdentity::generate();
            let (sender_platform, _sender_outbound) = TestPlatform::new(
                sender_identity.clone(),
                recipient_identity.encapsulation_public_key.clone(),
                recipient_identity.signing_public_key.clone(),
            );
            let (recipient_platform, _recipient_outbound) =
                TestPlatform::new_unpaired(recipient_identity.clone());
            let config = RuntimeConfig {
                default_timeout: Duration::from_secs(1),
            };
            let (mut core, handle, _incoming) = Runtime::new(recipient_platform.clone(), config);

            assert!(recipient_platform
                .lookup_peer(sender_identity.xid)
                .is_none());

            let (header, encrypted) = encrypt_pairing_request(
                &sender_platform,
                &recipient_identity.signing_public_key,
                &recipient_identity.encapsulation_public_key,
            )
            .expect("encrypt pairing request");
            let message = decode_ql_message(&encode_ql_message(header, encrypted))
                .expect("decode pairing request");
            let bytes = encode_ql_message(message.header, message.payload);

            tokio::task::spawn_local(async move { core.run().await });
            handle.send_incoming(bytes).unwrap();
            tokio::task::yield_now().await;

            let peer = recipient_platform
                .lookup_peer(sender_identity.xid)
                .expect("peer stored");
            assert!(peer.session().is_some());
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn reset_collision_prefers_lower_xid() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let client_identity = QlIdentity::generate();
            let server_identity = QlIdentity::generate();
            let (lower_identity, higher_identity) = if client_identity.xid < server_identity.xid {
                (client_identity.clone(), server_identity.clone())
            } else {
                (server_identity.clone(), client_identity.clone())
            };

            let (lower_platform, _lower_outbound) = TestPlatform::new(
                lower_identity.clone(),
                higher_identity.encapsulation_public_key.clone(),
                higher_identity.signing_public_key.clone(),
            );
            let (higher_platform, _higher_outbound) = TestPlatform::new(
                higher_identity.clone(),
                lower_identity.encapsulation_public_key.clone(),
                lower_identity.signing_public_key.clone(),
            );

            let config = RuntimeConfig {
                default_timeout: Duration::from_secs(1),
            };
            let (mut lower_core, lower_handle, _lower_incoming) =
                Runtime::new(lower_platform.clone(), config);
            let (mut higher_core, higher_handle, _higher_incoming) =
                Runtime::new(higher_platform.clone(), config);

            tokio::task::spawn_local(async move { lower_core.run().await });
            tokio::task::spawn_local(async move { higher_core.run().await });

            let lower_reset_id = bc_components::ARID::new();
            let higher_reset_id = bc_components::ARID::new();
            lower_platform.set_pending_handshake(Some(crate::runtime::PendingHandshake {
                kind: crate::runtime::HandshakeKind::SessionReset,
                origin: ResetOrigin::Local,
                id: lower_reset_id,
            }));
            higher_platform.set_pending_handshake(Some(crate::runtime::PendingHandshake {
                kind: crate::runtime::HandshakeKind::SessionReset,
                origin: ResetOrigin::Local,
                id: higher_reset_id,
            }));

            let reset_from_lower =
                build_reset_message(&lower_identity, &higher_identity, lower_reset_id);
            let reset_from_higher =
                build_reset_message(&higher_identity, &lower_identity, higher_reset_id);

            lower_handle
                .send_incoming(encode_ql_message(
                    reset_from_higher.header,
                    reset_from_higher.payload,
                ))
                .unwrap();
            higher_handle
                .send_incoming(encode_ql_message(
                    reset_from_lower.header,
                    reset_from_lower.payload,
                ))
                .unwrap();

            tokio::task::yield_now().await;

            assert_eq!(
                lower_platform.pending_handshake().map(|state| state.origin),
                Some(ResetOrigin::Local)
            );
            assert_eq!(
                higher_platform
                    .pending_handshake()
                    .map(|state| state.origin),
                Some(ResetOrigin::Peer)
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn reset_from_higher_xid_is_accepted_without_pending() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let client_identity = QlIdentity::generate();
            let server_identity = QlIdentity::generate();
            let (lower_identity, higher_identity) = if client_identity.xid < server_identity.xid {
                (client_identity.clone(), server_identity.clone())
            } else {
                (server_identity.clone(), client_identity.clone())
            };

            let (lower_platform, _lower_outbound) = TestPlatform::new(
                lower_identity.clone(),
                higher_identity.encapsulation_public_key.clone(),
                higher_identity.signing_public_key.clone(),
            );

            let config = RuntimeConfig {
                default_timeout: Duration::from_secs(1),
            };
            let (mut lower_core, lower_handle, _lower_incoming) =
                Runtime::new(lower_platform.clone(), config);
            tokio::task::spawn_local(async move { lower_core.run().await });

            let reset_from_higher = build_reset_message(
                &higher_identity,
                &lower_identity,
                bc_components::ARID::new(),
            );

            lower_handle
                .send_incoming(encode_ql_message(
                    reset_from_higher.header,
                    reset_from_higher.payload,
                ))
                .unwrap();

            tokio::task::yield_now().await;

            assert_eq!(
                lower_platform.pending_handshake().map(|state| state.origin),
                Some(ResetOrigin::Peer)
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn reset_with_invalid_signature_is_rejected() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let client_identity = QlIdentity::generate();
            let server_identity = QlIdentity::generate();
            let (platform, _outbound) = TestPlatform::new(
                client_identity.clone(),
                server_identity.encapsulation_public_key.clone(),
                server_identity.signing_public_key.clone(),
            );
            let config = RuntimeConfig {
                default_timeout: Duration::from_secs(1),
            };
            let (mut core, handle, _incoming) = Runtime::new(platform.clone(), config);
            tokio::task::spawn_local(async move { core.run().await });

            let id = bc_components::ARID::new();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            let valid_until = now.saturating_add(60);
            let (session_key, kem_ct) = client_identity
                .encapsulation_public_key
                .encapsulate_new_shared_secret();
            let header = QlHeader {
                kind: MessageKind::SessionReset,
                id,
                sender: server_identity.xid,
                recipient: client_identity.xid,
                valid_until,
                kem_ct: Some(kem_ct.clone()),
                signature: None,
            };
            let signature = Some(
                server_identity
                    .private_keys
                    .sign(&header.aad_data())
                    .expect("sign reset header"),
            );
            let header = QlHeader {
                signature,
                ..header
            };
            let aad = header.aad_data();
            let payload_bytes = CBOR::null().to_cbor_data();
            let encrypted =
                session_key.encrypt(payload_bytes, Some(aad), None::<bc_components::Nonce>);
            let mut reset_message =
                decode_ql_message(&encode_ql_message(header, encrypted)).expect("decode reset");
            reset_message.header.kind = MessageKind::Request;

            handle
                .send_incoming(encode_ql_message(
                    reset_message.header,
                    reset_message.payload,
                ))
                .unwrap();

            tokio::task::yield_now().await;

            let errors = platform.take_errors();
            assert!(errors
                .iter()
                .any(|error| matches!(error, QlError::InvalidSignature)));
        })
        .await;
}
