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

use super::{
    encrypt, Event, EventHandler, QlExecutorHandle, QlPayload, QlPeer, QlPlatform, QlRequest,
    RequestHandler, RequestResponse, ResetOrigin, Router,
};
use crate::{
    decode_ql_message, encode_ql_message, test_identity::TestIdentity, Executor, ExecutorConfig,
    ExecutorError, ExecutorPlatform, HandlerEvent, InboundEvent, MessageKind, PlatformFuture,
    QlError, QlHeader, QlMessage, RequestConfig,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ping(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pong(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Notice(u64);

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

impl RequestResponse for Ping {
    const ID: u64 = 100;
    type Response = Pong;
}

impl Event for Notice {
    const ID: u64 = 200;
}

struct TestPlatform {
    tx: Sender<Vec<u8>>,
}

impl TestPlatform {
    fn new() -> (Self, Receiver<Vec<u8>>) {
        let (tx, rx) = async_channel::unbounded();
        (Self { tx }, rx)
    }
}

impl ExecutorPlatform for TestPlatform {
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), ExecutorError>> {
        let tx = self.tx.clone();
        Box::pin(async move { tx.send(message).await.map_err(|_| ExecutorError::Cancelled) })
    }
    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

struct TestPeer {
    encapsulation_public_key: EncapsulationPublicKey,
    signing_public_key: SigningPublicKey,
    session: Mutex<Option<SymmetricKey>>,
    pending_handshake: Mutex<Option<super::PendingHandshake>>,
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

    fn pending_handshake(&self) -> Option<super::PendingHandshake> {
        *self.pending_handshake.lock().unwrap()
    }

    fn set_pending_handshake(&self, handshake: Option<super::PendingHandshake>) {
        let mut guard = self.pending_handshake.lock().unwrap();
        *guard = handshake;
    }
}

struct TestRouterPlatform {
    identity: TestIdentity,
    peer: Mutex<Option<Arc<TestPeer>>>,
}

impl TestRouterPlatform {
    fn new(
        identity: TestIdentity,
        peer: EncapsulationPublicKey,
        peer_signing_key: SigningPublicKey,
    ) -> Self {
        Self {
            identity,
            peer: Mutex::new(Some(Arc::new(TestPeer::new(peer, peer_signing_key)))),
        }
    }

    fn new_unpaired(identity: TestIdentity) -> Self {
        Self {
            identity,
            peer: Mutex::new(None),
        }
    }

    fn xid(&self) -> XID {
        self.identity.xid
    }

    fn pending_handshake(&self) -> Option<super::PendingHandshake> {
        self.peer
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().and_then(|peer| peer.pending_handshake()))
    }

    fn set_pending_handshake(&self, handshake: Option<super::PendingHandshake>) {
        let Ok(guard) = self.peer.lock() else {
            return;
        };
        let Some(peer) = guard.as_ref() else {
            return;
        };
        peer.set_pending_handshake(handshake);
    }
}

impl QlPlatform for TestRouterPlatform {
    type Peer = Arc<TestPeer>;

    fn lookup_peer(&self, peer: XID) -> Option<Self::Peer> {
        let guard = self.peer.lock().ok()?;
        let stored = guard.as_ref()?;
        if peer == XID::new(&stored.signing_public_key) {
            Some(stored.clone())
        } else {
            None
        }
    }

    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey {
        self.identity.private_keys.encapsulation_private_key()
    }

    fn encapsulation_public_key(&self) -> EncapsulationPublicKey {
        self.identity.encapsulation_public_key.clone()
    }

    fn signing_key(&self) -> &SigningPublicKey {
        &self.identity.signing_public_key
    }

    fn message_expiration(&self) -> Duration {
        Duration::from_secs(60)
    }

    fn signer(&self) -> &dyn Signer {
        &self.identity.private_keys
    }

    fn handle_error(&self, _e: super::QlError) {}

    fn store_peer(
        &self,
        _signing_pub_key: SigningPublicKey,
        _encapsulation_pub_key: EncapsulationPublicKey,
        _session: SymmetricKey,
    ) {
        let mut guard = self.peer.lock().unwrap();
        let peer = Arc::new(TestPeer::new(_encapsulation_pub_key, _signing_pub_key));
        peer.store_session(_session);
        *guard = Some(peer);
    }
}

struct TestState {
    event_tx: Option<oneshot::Sender<u64>>,
}

impl RequestHandler<Ping, TestRouterPlatform> for TestState {
    fn handle(&mut self, request: QlRequest<Ping, TestRouterPlatform>) {
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
    sender: &TestIdentity,
    recipient: &TestIdentity,
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
            let (client_platform, client_outbound) = TestPlatform::new();
            let (server_platform, server_outbound) = TestPlatform::new();
            let config = ExecutorConfig {
                default_timeout: Duration::from_secs(1),
            };

            let (mut client_core, client_handle, _client_incoming) =
                Executor::new(client_platform, config);
            let (mut server_core, server_handle, mut server_incoming) =
                Executor::new(server_platform, config);

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

            let client_identity = TestIdentity::generate();
            let server_identity = TestIdentity::generate();
            let client_platform = Arc::new(TestRouterPlatform::new(
                client_identity.clone(),
                server_identity.encapsulation_public_key.clone(),
                server_identity.signing_public_key.clone(),
            ));
            let server_platform = Arc::new(TestRouterPlatform::new(
                server_identity.clone(),
                client_identity.encapsulation_public_key.clone(),
                client_identity.signing_public_key.clone(),
            ));
            let recipient = server_platform.xid();

            let router = Router::builder(server_handle.clone())
                .add_request_handler::<Ping>()
                .add_event_handler::<Notice>()
                .build(server_platform.clone());

            let (event_tx, event_rx) = oneshot::channel();
            let mut state = TestState {
                event_tx: Some(event_tx),
            };

            tokio::task::spawn_local({
                let server_platform = server_platform.clone();
                async move {
                    loop {
                        let event = match server_incoming.next().await {
                            Ok(event) => event,
                            Err(_) => break,
                        };
                        if let Err(err) = router.handle(&mut state, event) {
                            server_platform.handle_error(err);
                        }
                    }
                }
            });

            let client_typed = QlExecutorHandle::new(client_handle, client_platform);

            client_typed
                .send_event(Notice(7), recipient, Duration::from_secs(60))
                .unwrap();
            let event_value = event_rx.await.expect("event handled");
            assert_eq!(event_value, 7);

            let response = client_typed
                .request(Ping(41), recipient, RequestConfig::default())
                .await
                .expect("response");
            assert_eq!(response, Pong(42));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn expired_response_is_rejected() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (platform, outbound_rx) = TestPlatform::new();
            let config = ExecutorConfig {
                default_timeout: Duration::from_secs(2),
            };
            let (mut core, handle, _incoming) = Executor::new(platform, config);
            tokio::task::spawn_local(async move { core.run().await });

            let requester = TestIdentity::generate();
            let responder = TestIdentity::generate();
            let requester_platform = Arc::new(TestRouterPlatform::new(
                requester.clone(),
                responder.encapsulation_public_key.clone(),
                responder.signing_public_key.clone(),
            ));
            let recipient = XID::new(&responder.signing_public_key);
            let client = QlExecutorHandle::new(handle.clone(), requester_platform.clone());

            let response_task = tokio::task::spawn_local(async move {
                client
                    .request(Ping(5), recipient, RequestConfig::default())
                    .await
            });

            let outbound = outbound_rx.recv().await.expect("no outbound request");
            let outbound_message = decode_ql_message(&outbound).expect("decode outbound");

            let session_key = requester_platform
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
            let (client_platform, client_outbound) = TestPlatform::new();
            let config = ExecutorConfig {
                default_timeout: Duration::from_secs(1),
            };
            let (mut client_core, client_handle, _client_incoming) =
                Executor::new(client_platform, config);
            tokio::task::spawn_local(async move { client_core.run().await });

            let client_identity = TestIdentity::generate();
            let server_identity = TestIdentity::generate();
            let client_platform = Arc::new(TestRouterPlatform::new(
                client_identity.clone(),
                server_identity.encapsulation_public_key.clone(),
                server_identity.signing_public_key.clone(),
            ));
            let recipient = XID::new(&server_identity.signing_public_key);
            let client_typed = QlExecutorHandle::new(client_handle.clone(), client_platform);

            let request_task = tokio::task::spawn_local(async move {
                client_typed
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
                Err(QlError::Send(ExecutorError::SessionReset)) => {}
                other => panic!("unexpected result: {other:?}"),
            }
        })
        .await;
}

#[test]
fn simultaneous_session_init_resolves() {
    fn expect_missing_handler(result: Result<(), QlError>) {
        assert!(matches!(result, Err(QlError::MissingHandler(_))));
    }

    fn build_event_message(
        platform: &Arc<TestRouterPlatform>,
        recipient: XID,
        notice: Notice,
    ) -> QlMessage {
        let payload = QlPayload {
            message_id: Notice::ID,
            payload: notice.into(),
        };
        let (header, encrypted) = encrypt::encrypt_payload_for_recipient(
            platform.as_ref(),
            recipient,
            MessageKind::Event,
            bc_components::ARID::new(),
            payload.into(),
        )
        .expect("encrypt event");
        decode_ql_message(&encode_ql_message(header, encrypted)).expect("decode event")
    }

    let (client_platform, _client_outbound) = TestPlatform::new();
    let (server_platform, _server_outbound) = TestPlatform::new();
    let config = ExecutorConfig {
        default_timeout: Duration::from_secs(1),
    };
    let (_client_core, client_handle, _client_incoming) = Executor::new(client_platform, config);
    let (_server_core, server_handle, _server_incoming) = Executor::new(server_platform, config);

    let client_identity = TestIdentity::generate();
    let server_identity = TestIdentity::generate();
    let client_router_platform = Arc::new(TestRouterPlatform::new(
        client_identity.clone(),
        server_identity.encapsulation_public_key.clone(),
        server_identity.signing_public_key.clone(),
    ));
    let server_router_platform = Arc::new(TestRouterPlatform::new(
        server_identity.clone(),
        client_identity.encapsulation_public_key.clone(),
        client_identity.signing_public_key.clone(),
    ));

    let client_router = Router::builder(client_handle).build(client_router_platform.clone());
    let server_router = Router::builder(server_handle).build(server_router_platform.clone());

    let from_client = build_event_message(
        &client_router_platform,
        server_router_platform.xid(),
        Notice(1),
    );
    let from_server = build_event_message(
        &server_router_platform,
        client_router_platform.xid(),
        Notice(2),
    );

    let server_result = server_router.handle(
        &mut TestState { event_tx: None },
        HandlerEvent::Event(InboundEvent {
            message: from_client,
        }),
    );
    let client_result = client_router.handle(
        &mut TestState { event_tx: None },
        HandlerEvent::Event(InboundEvent {
            message: from_server,
        }),
    );

    if client_router_platform.xid() < server_router_platform.xid() {
        assert!(matches!(client_result, Err(QlError::SessionInitCollision)));
        expect_missing_handler(server_result);
    } else {
        assert!(matches!(server_result, Err(QlError::SessionInitCollision)));
        expect_missing_handler(client_result);
    }

    let follow_up_from_client = build_event_message(
        &client_router_platform,
        server_router_platform.xid(),
        Notice(3),
    );
    let follow_up_from_server = build_event_message(
        &server_router_platform,
        client_router_platform.xid(),
        Notice(4),
    );

    expect_missing_handler(server_router.handle(
        &mut TestState { event_tx: None },
        HandlerEvent::Event(InboundEvent {
            message: follow_up_from_client,
        }),
    ));
    expect_missing_handler(client_router.handle(
        &mut TestState { event_tx: None },
        HandlerEvent::Event(InboundEvent {
            message: follow_up_from_server,
        }),
    ));
}

#[test]
fn pairing_request_stores_peer() {
    let (platform, _outbound) = TestPlatform::new();
    let config = ExecutorConfig {
        default_timeout: Duration::from_secs(1),
    };
    let (_core, handle, _incoming) = Executor::new(platform, config);

    let sender_identity = TestIdentity::generate();
    let recipient_identity = TestIdentity::generate();
    let sender_platform = Arc::new(TestRouterPlatform::new(
        sender_identity.clone(),
        recipient_identity.encapsulation_public_key.clone(),
        recipient_identity.signing_public_key.clone(),
    ));
    let recipient_platform = Arc::new(TestRouterPlatform::new_unpaired(recipient_identity.clone()));
    let router = Router::builder(handle).build(recipient_platform.clone());

    assert!(recipient_platform
        .lookup_peer(sender_identity.xid)
        .is_none());

    let (header, encrypted) = encrypt::encrypt_pairing_request(
        sender_platform.as_ref(),
        &recipient_identity.signing_public_key,
        &recipient_identity.encapsulation_public_key,
    )
    .expect("encrypt pairing request");
    let message =
        decode_ql_message(&encode_ql_message(header, encrypted)).expect("decode pairing request");

    router
        .handle(
            &mut TestState { event_tx: None },
            HandlerEvent::Event(InboundEvent { message }),
        )
        .expect("pairing handled");

    let peer = recipient_platform
        .lookup_peer(sender_identity.xid)
        .expect("peer stored");
    assert!(peer.session().is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn reset_collision_prefers_lower_xid() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (client_platform, _client_outbound) = TestPlatform::new();
            let (server_platform, _server_outbound) = TestPlatform::new();
            let config = ExecutorConfig {
                default_timeout: Duration::from_secs(1),
            };
            let (_client_core, client_handle, _client_incoming) =
                Executor::new(client_platform, config);
            let (_server_core, server_handle, _server_incoming) =
                Executor::new(server_platform, config);

            let client_identity = TestIdentity::generate();
            let server_identity = TestIdentity::generate();
            let (lower_identity, higher_identity) = if client_identity.xid < server_identity.xid {
                (client_identity.clone(), server_identity.clone())
            } else {
                (server_identity.clone(), client_identity.clone())
            };

            let lower_platform = Arc::new(TestRouterPlatform::new(
                lower_identity.clone(),
                higher_identity.encapsulation_public_key.clone(),
                higher_identity.signing_public_key.clone(),
            ));
            let higher_platform = Arc::new(TestRouterPlatform::new(
                higher_identity.clone(),
                lower_identity.encapsulation_public_key.clone(),
                lower_identity.signing_public_key.clone(),
            ));

            let lower_router = Router::builder(client_handle).build(lower_platform.clone());
            let higher_router = Router::builder(server_handle).build(higher_platform.clone());

            let lower_reset_id = bc_components::ARID::new();
            let higher_reset_id = bc_components::ARID::new();
            lower_platform.set_pending_handshake(Some(super::PendingHandshake {
                kind: super::HandshakeKind::SessionReset,
                origin: ResetOrigin::Local,
                id: lower_reset_id,
            }));
            higher_platform.set_pending_handshake(Some(super::PendingHandshake {
                kind: super::HandshakeKind::SessionReset,
                origin: ResetOrigin::Local,
                id: higher_reset_id,
            }));

            let reset_from_lower =
                build_reset_message(&lower_identity, &higher_identity, lower_reset_id);
            let reset_from_higher =
                build_reset_message(&higher_identity, &lower_identity, higher_reset_id);

            lower_router
                .handle(
                    &mut TestState { event_tx: None },
                    HandlerEvent::Event(InboundEvent {
                        message: reset_from_higher,
                    }),
                )
                .unwrap();
            higher_router
                .handle(
                    &mut TestState { event_tx: None },
                    HandlerEvent::Event(InboundEvent {
                        message: reset_from_lower,
                    }),
                )
                .unwrap();

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
            let (platform, _outbound) = TestPlatform::new();
            let config = ExecutorConfig {
                default_timeout: Duration::from_secs(1),
            };
            let (_core, handle, _incoming) = Executor::new(platform, config);

            let client_identity = TestIdentity::generate();
            let server_identity = TestIdentity::generate();
            let (lower_identity, higher_identity) = if client_identity.xid < server_identity.xid {
                (client_identity.clone(), server_identity.clone())
            } else {
                (server_identity.clone(), client_identity.clone())
            };

            let lower_platform = Arc::new(TestRouterPlatform::new(
                lower_identity.clone(),
                higher_identity.encapsulation_public_key.clone(),
                higher_identity.signing_public_key.clone(),
            ));

            let lower_router = Router::builder(handle).build(lower_platform.clone());

            let reset_from_higher = build_reset_message(
                &higher_identity,
                &lower_identity,
                bc_components::ARID::new(),
            );

            lower_router
                .handle(
                    &mut TestState { event_tx: None },
                    HandlerEvent::Event(InboundEvent {
                        message: reset_from_higher,
                    }),
                )
                .unwrap();

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
            let (platform, _outbound) = TestPlatform::new();
            let config = ExecutorConfig {
                default_timeout: Duration::from_secs(1),
            };
            let (_core, handle, _incoming) = Executor::new(platform, config);

            let client_identity = TestIdentity::generate();
            let server_identity = TestIdentity::generate();
            let router_platform = Arc::new(TestRouterPlatform::new(
                client_identity.clone(),
                server_identity.encapsulation_public_key.clone(),
                server_identity.signing_public_key.clone(),
            ));
            let router = Router::builder(handle).build(router_platform.clone());

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

            let result = router.handle(
                &mut TestState { event_tx: None },
                HandlerEvent::Event(InboundEvent {
                    message: reset_message,
                }),
            );

            assert!(matches!(result, Err(QlError::InvalidSignature)));
        })
        .await;
}
