use std::{sync::Arc, time::Duration};

use async_channel::{Receiver, Sender};
use bc_components::{EncapsulationPublicKey, Signer, SigningPublicKey, XID};
use bc_envelope::Envelope;
use dcbor::CBOR;

use super::{
    Event, EventHandler, RequestHandler, RequestResponse, Router, RouterPlatform,
    TypedExecutorHandle, TypedRequest,
};
use crate::{
    test_identity::TestIdentity, Executor, ExecutorConfig, PlatformFuture, QlError, QlPlatform,
    RequestConfig,
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

impl QlPlatform for TestPlatform {
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>> {
        let tx = self.tx.clone();
        Box::pin(async move { tx.send(message).await.map_err(|_| QlError::Cancelled) })
    }

    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()> {
        Box::pin(async move { tokio::time::sleep(duration).await })
    }
}

struct TestRouterPlatform {
    identity: TestIdentity,
    peer: EncapsulationPublicKey,
}

impl TestRouterPlatform {
    fn new(identity: TestIdentity, peer: EncapsulationPublicKey) -> Self {
        Self { identity, peer }
    }

    fn xid(&self) -> XID {
        self.identity.xid
    }
}

impl RouterPlatform for TestRouterPlatform {
    fn decrypt_payload(&self, payload: Envelope) -> Result<CBOR, super::RouterError> {
        let private_keys = &self.identity.private_keys;
        let decrypted = payload
            .decrypt_to_recipient(private_keys)
            .map_err(|error| super::RouterError::Decode(error.into()))?;
        decrypted
            .as_leaf()
            .ok_or_else(|| super::RouterError::Decode(dcbor::Error::msg("expected leaf payload")))
    }

    fn lookup_recipient(&self, _recipient: XID) -> Option<&bc_components::EncapsulationPublicKey> {
        Some(&self.peer)
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

    fn handle_error(&self, _e: super::RouterError) {}
}

struct TestState {
    event_tx: Option<oneshot::Sender<u64>>,
}

impl RequestHandler<Ping> for TestState {
    fn handle(&mut self, request: TypedRequest<Ping>) {
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
            ));
            let server_platform = Arc::new(TestRouterPlatform::new(
                server_identity.clone(),
                client_identity.encapsulation_public_key.clone(),
            ));
            let recipient = server_platform.xid();

            let router = Router::builder()
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

            let client_typed = TypedExecutorHandle::new(client_handle, client_platform);

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
