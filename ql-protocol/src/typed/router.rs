use std::{collections::HashMap, sync::Arc};

use bc_components::{Verifier, XID};
use dcbor::CBOR;

use super::{Event, QlCodec, RequestResponse, RouterError, RouterPlatform, TypedPayload};
use crate::{EncodeQlConfig, ExecutorHandle, HandlerEvent, MessageKind, QlHeader, Responder};

pub trait RequestHandler<M>
where
    M: RequestResponse,
{
    fn handle(&mut self, request: TypedRequest<M>);
    fn default_response() -> M::Response;
}

pub trait EventHandler<M>
where
    M: Event,
{
    fn handle(&mut self, event: M);
}

pub struct TypedRequest<M>
where
    M: RequestResponse,
{
    pub message: M,
    pub responder: TypedResponder<M::Response>,
}

pub struct TypedResponder<R>
where
    R: QlCodec,
{
    responder: Option<Responder>,
    platform: Arc<dyn RouterPlatform>,
    recipient: XID,
    default: fn() -> R,
}

impl<R> TypedResponder<R>
where
    R: QlCodec,
{
    pub fn respond(mut self, response: R) -> Result<(), RouterError> {
        self.respond_inner(response)
    }

    fn respond_inner(&mut self, response: R) -> Result<(), RouterError> {
        let responder = self.responder.take().unwrap();
        let payload = response.into();
        let session_key = self
            .platform
            .session_for_peer(self.recipient)
            .ok_or(RouterError::MissingSession(self.recipient))?;
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

impl<R> Drop for TypedResponder<R>
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

type RouterHandler<S> = fn(&mut S, RouterEvent, Arc<dyn RouterPlatform>) -> Result<(), RouterError>;

enum RouterEvent {
    Event {
        #[allow(unused)]
        header: QlHeader,
        payload: TypedPayload,
    },
    Request {
        header: QlHeader,
        payload: TypedPayload,
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
}

impl<S> RouterBuilder<S> {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
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

    pub fn build(self, platform: Arc<dyn RouterPlatform>, executor: ExecutorHandle) -> Router<S> {
        Router {
            platform,
            handlers: self.handlers,
            executor,
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
    platform: Arc<dyn RouterPlatform>,
    handlers: HashMap<u64, RouterHandler<S>>,
    executor: ExecutorHandle,
}

impl<S> Router<S> {
    pub fn builder() -> RouterBuilder<S> {
        RouterBuilder::new()
    }

    pub fn handle(&self, state: &mut S, event: HandlerEvent) -> Result<(), RouterError> {
        let sender = match &event {
            HandlerEvent::Request(request) => &request.message.header,
            HandlerEvent::Event(event) => &event.message.header,
        };
        let sender = sender.sender;
        let event = match decrypt_event(event, self.platform.as_ref()) {
            Ok(event) => event,
            Err(error) => {
                if matches!(
                    error,
                    RouterError::MissingSession(_) | RouterError::InvalidPayload
                ) {
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
                    .ok_or(RouterError::MissingHandler(message_id))?;
                handler(state, event, self.platform.clone())
            }
        }
    }
}

impl<S> Router<S> {
    fn send_session_reset(&self, recipient: XID) -> Result<(), RouterError> {
        let executor = self.executor.clone();
        let recipient_key = self
            .platform
            .lookup_recipient(recipient)
            .ok_or(RouterError::UnknownRecipient(recipient))?;
        let (session_key, kem_ct) = recipient_key.encapsulate_new_shared_secret();
        self.platform.store_session(recipient, session_key.clone());

        let now = now_secs();
        let valid_until = now.saturating_add(self.platform.message_expiration().as_secs());
        let id = bc_components::ARID::new();
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
    platform: Arc<dyn RouterPlatform>,
) -> Result<(), RouterError>
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
    let responder = TypedResponder {
        responder: Some(responder),
        platform,
        recipient: header.sender,
        default: S::default_response,
    };
    state.handle(TypedRequest { message, responder });
    Ok(())
}

fn handle_event<M, S>(
    state: &mut S,
    event: RouterEvent,
    _platform: Arc<dyn RouterPlatform>,
) -> Result<(), RouterError>
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

fn decrypt_event(
    event: HandlerEvent,
    platform: &dyn RouterPlatform,
) -> Result<RouterEvent, RouterError> {
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

fn verify_header(platform: &dyn RouterPlatform, header: &QlHeader) -> Result<(), RouterError> {
    if header.kem_ct.is_none() {
        return Ok(());
    }
    let signature = header
        .signature
        .as_ref()
        .ok_or(RouterError::InvalidSignature)?;
    let signing_key = platform
        .lookup_signing_key(header.sender)
        .ok_or(RouterError::UnknownSender(header.sender))?;
    if signing_key.verify(signature, &header.aad_data()) {
        Ok(())
    } else {
        Err(RouterError::InvalidSignature)
    }
}

fn extract_typed_payload(
    platform: &dyn RouterPlatform,
    header: &QlHeader,
    payload: bc_components::EncryptedMessage,
) -> Result<TypedPayload, RouterError> {
    let session_key = if let Some(kem_ct) = &header.kem_ct {
        let key = platform.decapsulate_shared_secret(kem_ct)?;
        platform.store_session(header.sender, key.clone());
        key
    } else {
        platform
            .session_for_peer(header.sender)
            .ok_or(RouterError::MissingSession(header.sender))?
    };
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), &payload)?;
    TypedPayload::try_from(decrypted).map_err(RouterError::Decode)
}

fn extract_reset_payload(
    platform: &dyn RouterPlatform,
    header: &QlHeader,
    payload: bc_components::EncryptedMessage,
) -> Result<(), RouterError> {
    let kem_ct = header.kem_ct.as_ref().ok_or(RouterError::InvalidPayload)?;
    let session_key = platform.decapsulate_shared_secret(kem_ct)?;
    platform.store_session(header.sender, session_key.clone());
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), &payload)?;
    if !decrypted.is_null() {
        return Err(RouterError::InvalidPayload);
    }
    Ok(())
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
