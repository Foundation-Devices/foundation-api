use std::{collections::HashMap, sync::Arc};

use bc_components::{Verifier, ARID, XID};
use dcbor::CBOR;

use super::{Event, QlCodec, QlError, QlPayload, QlPlatform, RequestResponse, ResetOrigin};
use crate::{EncodeQlConfig, ExecutorHandle, HandlerEvent, MessageKind, QlHeader, Responder};

pub trait RequestHandler<M>
where
    M: RequestResponse,
{
    fn handle(&mut self, request: QlRequest<M>);
    fn default_response() -> M::Response;
}

pub trait EventHandler<M>
where
    M: Event,
{
    fn handle(&mut self, event: M);
}

pub struct QlRequest<M>
where
    M: RequestResponse,
{
    pub message: M,
    pub responder: QlResponder<M::Response>,
}

pub struct QlResponder<R>
where
    R: QlCodec,
{
    responder: Option<Responder>,
    platform: Arc<dyn QlPlatform>,
    recipient: XID,
    default: fn() -> R,
}

impl<R> QlResponder<R>
where
    R: QlCodec,
{
    pub fn respond(mut self, response: R) -> Result<(), QlError> {
        self.respond_inner(response)
    }

    fn respond_inner(&mut self, response: R) -> Result<(), QlError> {
        let responder = self.responder.take().unwrap();
        let payload = response.into();
        let peer = self.platform.lookup_peer_or_fail(self.recipient)?;
        let session_key = peer
            .session()
            .ok_or(QlError::MissingSession(self.recipient))?;
        let now = now_secs();
        let valid_until = now.saturating_add(self.platform.message_expiration().as_secs());
        let header_unsigned = QlHeader {
            kind: MessageKind::Response,
            id: responder.id(),
            sender: self.platform.sender_xid(),
            recipient: self.recipient,
            valid_until,
            kem_ct: None,
            signature: None,
        };
        let aad = header_unsigned.aad_data();
        let payload_bytes = dcbor::CBOR::from(payload).to_cbor_data();
        let encrypted = session_key.encrypt(payload_bytes, Some(aad), None::<bc_components::Nonce>);
        let config = EncodeQlConfig {
            sender: self.platform.sender_xid(),
            recipient: self.recipient,
            valid_until,
            kem_ct: None,
            sign_header: false,
        };
        responder.respond(encrypted, config, self.platform.signer())?;
        Ok(())
    }
}

impl<R> Drop for QlResponder<R>
where
    R: QlCodec,
{
    fn drop(&mut self) {
        if self.responder.is_some() {
            let default = (self.default)();
            let _ = self.respond_inner(default);
        }
    }
}

type RouterHandler<S> = fn(&mut S, RouterEvent, Arc<dyn QlPlatform>) -> Result<(), QlError>;

enum RouterEvent {
    Event {
        #[allow(unused)]
        header: QlHeader,
        payload: QlPayload,
    },
    Request {
        header: QlHeader,
        payload: QlPayload,
        responder: Responder,
    },
    SessionReset {
        #[allow(dead_code)]
        header: QlHeader,
    },
}

impl RouterEvent {
    fn message_id(&self) -> u64 {
        match self {
            RouterEvent::Event { payload, .. } => payload.message_id,
            RouterEvent::Request { payload, .. } => payload.message_id,
            RouterEvent::SessionReset { .. } => 0,
        }
    }
}

pub struct RouterBuilder<S> {
    handlers: HashMap<u64, RouterHandler<S>>,
    executor: ExecutorHandle,
}

impl<S> RouterBuilder<S> {
    pub fn new(executor: ExecutorHandle) -> Self {
        Self {
            handlers: HashMap::new(),
            executor,
        }
    }

    pub fn add_request_handler<M>(self) -> Self
    where
        M: RequestResponse,
        S: RequestHandler<M>,
    {
        self.add_handler(M::ID, handle_request::<M, S>)
    }

    pub fn add_event_handler<M>(self) -> Self
    where
        M: Event,
        S: EventHandler<M>,
    {
        self.add_handler(M::ID, handle_event::<M, S>)
    }

    pub fn build(self, platform: Arc<dyn QlPlatform>) -> Router<S> {
        Router {
            platform,
            handlers: self.handlers,
            executor: self.executor,
        }
    }

    fn add_handler(mut self, id: u64, handler: RouterHandler<S>) -> Self {
        if self.handlers.insert(id, handler).is_some() {
            panic!("duplicate message_id {id}")
        }
        self
    }
}

pub struct Router<S> {
    platform: Arc<dyn QlPlatform>,
    handlers: HashMap<u64, RouterHandler<S>>,
    executor: ExecutorHandle,
}

impl<S> Router<S> {
    pub fn builder(executor: ExecutorHandle) -> RouterBuilder<S> {
        RouterBuilder::new(executor)
    }

    pub fn handle(&self, state: &mut S, event: HandlerEvent) -> Result<(), QlError> {
        let sender = match &event {
            HandlerEvent::Request(request) => &request.message.header,
            HandlerEvent::Event(event) => &event.message.header,
        };
        let sender = sender.sender;
        let event = match decrypt_event(event, self.platform.as_ref()) {
            Ok(event) => event,
            Err(error) => {
                if matches!(error, QlError::MissingSession(_) | QlError::InvalidPayload) {
                    let _ = self.send_session_reset(sender);
                }
                return Err(error);
            }
        };
        match event {
            RouterEvent::SessionReset { .. } => Ok(()),
            RouterEvent::Event { .. } | RouterEvent::Request { .. } => {
                let message_id = event.message_id();
                let handler = self
                    .handlers
                    .get(&message_id)
                    .ok_or(QlError::MissingHandler(message_id))?;
                handler(state, event, self.platform.clone())
            }
        }
    }
}

impl<S> Router<S> {
    fn send_session_reset(&self, recipient: XID) -> Result<(), QlError> {
        let executor = self.executor.clone();
        let peer = self.platform.lookup_peer_or_fail(recipient)?;
        let recipient_key = peer.encapsulation_pub_key();
        let (session_key, kem_ct) = recipient_key.encapsulate_new_shared_secret();
        peer.store_session(session_key.clone());

        let now = now_secs();
        let valid_until = now.saturating_add(self.platform.message_expiration().as_secs());
        let id = bc_components::ARID::new();
        peer.set_pending_reset(super::ResetOrigin::Local, id);
        let header_unsigned = QlHeader {
            kind: MessageKind::SessionReset,
            id,
            sender: self.platform.sender_xid(),
            recipient,
            valid_until,
            kem_ct: Some(kem_ct.clone()),
            signature: None,
        };
        let aad = header_unsigned.aad_data();
        let payload_bytes = CBOR::null().to_cbor_data();
        let encrypted = session_key.encrypt(payload_bytes, Some(aad), None::<bc_components::Nonce>);
        let config = EncodeQlConfig {
            sender: self.platform.sender_xid(),
            recipient,
            valid_until,
            kem_ct: Some(kem_ct),
            sign_header: true,
        };
        executor.send_message(
            MessageKind::SessionReset,
            id,
            encrypted,
            config,
            self.platform.signer(),
        );
        Ok(())
    }
}

fn handle_request<M, S>(
    state: &mut S,
    event: RouterEvent,
    platform: Arc<dyn QlPlatform>,
) -> Result<(), QlError>
where
    M: RequestResponse,
    S: RequestHandler<M>,
{
    let (header, payload, responder) = match event {
        RouterEvent::Request {
            header,
            payload,
            responder,
        } => (header, payload, responder),
        RouterEvent::Event { .. } => unreachable!("expected request event"),
        RouterEvent::SessionReset { .. } => unreachable!("expected request event"),
    };
    let message = M::try_from(payload.payload)?;
    let responder = QlResponder {
        responder: Some(responder),
        platform,
        recipient: header.sender,
        default: S::default_response,
    };
    state.handle(QlRequest { message, responder });
    Ok(())
}

fn handle_event<M, S>(
    state: &mut S,
    event: RouterEvent,
    _platform: Arc<dyn QlPlatform>,
) -> Result<(), QlError>
where
    M: Event,
    S: EventHandler<M>,
{
    let payload = match event {
        RouterEvent::Event { payload, .. } => payload,
        RouterEvent::Request { .. } => unreachable!("expected event"),
        RouterEvent::SessionReset { .. } => unreachable!("expected event"),
    };
    let message = M::try_from(payload.payload)?;
    state.handle(message);
    Ok(())
}

fn decrypt_event(event: HandlerEvent, platform: &dyn QlPlatform) -> Result<RouterEvent, QlError> {
    match event {
        HandlerEvent::Request(request) => {
            verify_header(platform, &request.message.header)?;
            let payload =
                extract_typed_payload(platform, &request.message.header, request.message.payload)?;
            Ok(RouterEvent::Request {
                header: request.message.header,
                payload,
                responder: request.respond_to,
            })
        }
        HandlerEvent::Event(event) => {
            verify_header(platform, &event.message.header)?;
            match event.message.header.kind {
                MessageKind::SessionReset => {
                    extract_reset_payload(platform, &event.message.header, event.message.payload)?;
                    Ok(RouterEvent::SessionReset {
                        header: event.message.header,
                    })
                }
                _ => {
                    let payload = extract_typed_payload(
                        platform,
                        &event.message.header,
                        event.message.payload,
                    )?;
                    Ok(RouterEvent::Event {
                        header: event.message.header,
                        payload,
                    })
                }
            }
        }
    }
}

fn verify_header(platform: &dyn QlPlatform, header: &QlHeader) -> Result<(), QlError> {
    if header.kem_ct.is_none() {
        return Ok(());
    }
    let signature = header.signature.as_ref().ok_or(QlError::InvalidSignature)?;
    let peer = platform.lookup_peer_or_fail(header.sender)?;
    let signing_key = peer.signing_pub_key();
    if signing_key.verify(signature, &header.aad_data()) {
        Ok(())
    } else {
        Err(QlError::InvalidSignature)
    }
}

fn extract_typed_payload(
    platform: &dyn QlPlatform,
    header: &QlHeader,
    payload: bc_components::EncryptedMessage,
) -> Result<QlPayload, QlError> {
    let peer = platform.lookup_peer_or_fail(header.sender)?;
    let session_key = if let Some(kem_ct) = &header.kem_ct {
        let key = platform.decapsulate_shared_secret(kem_ct)?;
        peer.store_session(key.clone());
        key
    } else {
        peer.session()
            .ok_or(QlError::MissingSession(header.sender))?
    };
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), &payload)?;
    peer.clear_pending_reset();
    QlPayload::try_from(decrypted).map_err(QlError::Decode)
}

fn extract_reset_payload(
    platform: &dyn QlPlatform,
    header: &QlHeader,
    payload: bc_components::EncryptedMessage,
) -> Result<(), QlError> {
    let peer = platform.lookup_peer_or_fail(header.sender)?;
    if let Some(pending) = peer.pending_reset() {
        if pending.origin == ResetOrigin::Local {
            let cmp = reset_cmp(header.sender, header.id, platform.sender_xid(), pending.id);
            if cmp != std::cmp::Ordering::Less {
                return Ok(());
            }
        }
    }
    let kem_ct = header.kem_ct.as_ref().ok_or(QlError::InvalidPayload)?;
    let session_key = platform.decapsulate_shared_secret(kem_ct)?;
    peer.store_session(session_key.clone());
    peer.set_pending_reset(ResetOrigin::Peer, header.id);
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), &payload)?;
    if !decrypted.is_null() {
        return Err(QlError::InvalidPayload);
    }
    Ok(())
}

fn reset_cmp(
    sender: XID,
    sender_id: ARID,
    local_origin: XID,
    local_id: ARID,
) -> std::cmp::Ordering {
    match sender.cmp(&local_origin) {
        std::cmp::Ordering::Equal => sender_id.data().cmp(local_id.data()),
        order => order,
    }
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
