use std::{collections::HashMap, sync::Arc};

use bc_components::XID;
use bc_envelope::Envelope;

use super::{Event, QlCodec, RequestResponse, RouterError, RouterPlatform, TypedPayload};
use crate::v2::{HandlerEvent, InboundEvent, InboundRequest, QlHeader, Responder};

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
        let envelope = self.platform.encrypt_payload(payload, self.recipient);
        responder.respond(
            envelope,
            self.platform.signing_key(),
            self.platform.response_valid_for(),
            self.platform.signer(),
        )?;
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
}

impl RouterEvent {
    fn message_id(&self) -> u64 {
        match self {
            RouterEvent::Event { payload, .. } => payload.message_id,
            RouterEvent::Request { payload, .. } => payload.message_id,
        }
    }
}

pub struct RouterBuilder<S> {
    handlers: HashMap<u64, RouterHandler<S>>,
}

impl<S> Default for RouterBuilder<S> {
    fn default() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }
}

impl<S> RouterBuilder<S> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_request_handler<M>(mut self) -> Self
    where
        M: RequestResponse,
        S: RequestHandler<M>,
    {
        self.handlers.insert(M::ID, handle_request::<M, S>);
        self
    }

    pub fn add_event_handler<M>(mut self) -> Self
    where
        M: Event,
        S: EventHandler<M>,
    {
        self.handlers.insert(M::ID, handle_event::<M, S>);
        self
    }

    pub fn build(self, platform: Arc<dyn RouterPlatform>) -> Router<S> {
        Router {
            platform,
            handlers: self.handlers,
        }
    }
}

pub struct Router<S> {
    platform: Arc<dyn RouterPlatform>,
    handlers: HashMap<u64, RouterHandler<S>>,
}

impl<S> Router<S> {
    pub fn builder() -> RouterBuilder<S> {
        RouterBuilder::new()
    }

    pub fn handle(&self, state: &mut S, event: HandlerEvent) -> Result<(), RouterError> {
        let event = decrypt_event(event, self.platform.as_ref())?;
        let message_id = event.message_id();
        let handler = self
            .handlers
            .get(&message_id)
            .ok_or(RouterError::MissingHandler(message_id))?;
        handler(state, event, self.platform.clone())
    }

    pub fn handle_request(
        &self,
        state: &mut S,
        request: InboundRequest,
    ) -> Result<(), RouterError> {
        self.handle(state, HandlerEvent::Request(request))
    }

    pub fn handle_event(&self, state: &mut S, event: InboundEvent) -> Result<(), RouterError> {
        self.handle(state, HandlerEvent::Event(event))
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
    };
    let message = M::try_from(payload.payload)?;
    let responder = TypedResponder {
        responder: Some(responder),
        platform,
        recipient: header.sender_xid(),
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
            let payload = extract_typed_payload(platform, request.message.payload)?;
            Ok(RouterEvent::Request {
                header: request.message.header,
                payload,
                responder: request.respond_to,
            })
        }
        HandlerEvent::Event(event) => {
            let payload = extract_typed_payload(platform, event.message.payload)?;
            Ok(RouterEvent::Event {
                header: event.message.header,
                payload,
            })
        }
    }
}

fn extract_typed_payload(
    platform: &dyn RouterPlatform,
    payload: Envelope,
) -> Result<TypedPayload, RouterError> {
    let decrypted = platform.decrypt_payload(payload)?;
    TypedPayload::try_from(decrypted).map_err(RouterError::Decode)
}
