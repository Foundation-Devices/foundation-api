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
    Event, EventHandler, QlExecutorHandle, QlPeer, QlPlatform, QlRequest, RequestHandler,
    RequestResponse, ResetOrigin, Router,
};
use crate::{
    decode_ql_message, encode_ql_message, test_identity::TestIdentity, EncodeQlConfig, Executor,
    ExecutorConfig, ExecutorError, ExecutorPlatform, HandlerEvent, InboundEvent, MessageKind,
    PlatformFuture, QlError, QlHeader, QlMessage, RequestConfig,
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
    pending_reset: Mutex<Option<super::QlResetState>>,
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
            pending_reset: Mutex::new(None),
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
        self.session.lock().ok().and_then(|guard| guard.clone())
    }

    fn store_session(&self, key: SymmetricKey) {
        if let Ok(mut guard) = self.session.lock() {
            *guard = Some(key);
        }
    }

    fn pending_reset(&self) -> Option<super::QlResetState> {
        self.pending_reset.lock().ok().and_then(|guard| *guard)
    }

    fn set_pending_reset(&self, origin: ResetOrigin, id: bc_components::ARID) {
        if let Ok(mut guard) = self.pending_reset.lock() {
            *guard = Some(super::QlResetState { origin, id });
        }
    }

    fn clear_pending_reset(&self) {
        if let Ok(mut guard) = self.pending_reset.lock() {
            *guard = None;
        }
    }
}

struct TestRouterPlatform {
    identity: TestIdentity,
    peer: TestPeer,
}

impl TestRouterPlatform {
    fn new(
        identity: TestIdentity,
        peer: EncapsulationPublicKey,
        peer_signing_key: SigningPublicKey,
    ) -> Self {
        Self {
            identity,
            peer: TestPeer::new(peer, peer_signing_key),
        }
    }

    fn xid(&self) -> XID {
        self.identity.xid
    }

    fn pending_reset(&self) -> Option<super::QlResetState> {
        self.peer.pending_reset()
    }

    fn set_pending_reset(&self, origin: ResetOrigin, id: bc_components::ARID) {
        self.peer.set_pending_reset(origin, id);
    }
}

impl QlPlatform for TestRouterPlatform {
    fn lookup_peer(&self, peer: XID) -> Option<&dyn QlPeer> {
        if peer == XID::new(&self.peer.signing_public_key) {
            Some(&self.peer)
        } else {
            None
        }
    }

    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey {
        self.identity.private_keys.encapsulation_private_key()
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
    let aad = header.aad_data();
    let payload_bytes = CBOR::null().to_cbor_data();
    let encrypted = session_key.encrypt(payload_bytes, Some(aad), None::<bc_components::Nonce>);
    let bytes = encode_ql_message(
        MessageKind::SessionReset,
        id,
        EncodeQlConfig {
            sender: sender.xid,
            recipient: recipient.xid,
            valid_until,
            kem_ct: Some(kem_ct),
            sign_header: true,
        },
        encrypted,
        &sender.private_keys,
    );
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
            let reset_bytes = encode_ql_message(
                reset_message.header.kind,
                reset_message.header.id,
                EncodeQlConfig {
                    sender: reset_message.header.sender,
                    recipient: reset_message.header.recipient,
                    valid_until: reset_message.header.valid_until,
                    kem_ct: reset_message.header.kem_ct.clone(),
                    sign_header: reset_message.header.signature.is_some(),
                },
                reset_message.payload,
                &server_identity.private_keys,
            );
            client_handle.send_incoming(reset_bytes).unwrap();

            let result = request_task.await.unwrap();
            match result {
                Err(QlError::Send(ExecutorError::SessionReset)) => {}
                other => panic!("unexpected result: {other:?}"),
            }
        })
        .await;
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
            lower_platform.set_pending_reset(ResetOrigin::Local, lower_reset_id);
            higher_platform.set_pending_reset(ResetOrigin::Local, higher_reset_id);

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
                lower_platform.pending_reset().map(|state| state.origin),
                Some(ResetOrigin::Local)
            );
            assert_eq!(
                higher_platform.pending_reset().map(|state| state.origin),
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
                lower_platform.pending_reset().map(|state| state.origin),
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
            let aad = header.aad_data();
            let payload_bytes = CBOR::null().to_cbor_data();
            let encrypted =
                session_key.encrypt(payload_bytes, Some(aad), None::<bc_components::Nonce>);
            let mut reset_message = decode_ql_message(&encode_ql_message(
                MessageKind::SessionReset,
                id,
                EncodeQlConfig {
                    sender: server_identity.xid,
                    recipient: client_identity.xid,
                    valid_until,
                    kem_ct: Some(kem_ct),
                    sign_header: true,
                },
                encrypted,
                &server_identity.private_keys,
            ))
            .expect("decode reset");
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
