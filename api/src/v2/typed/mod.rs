use std::{collections::HashMap, sync::Arc, time::Duration};

use bc_components::{Signer, SigningPublicKey, XID};
use bc_envelope::Envelope;
use dcbor::CBOR;

use crate::v2::{
    EncodeQlConfig,
    ExecutorHandle,
    HandlerEvent,
    InboundEvent,
    InboundRequest,
    QlError,
    QlHeader,
    RequestConfig,
    Responder,
};

pub trait QlCodec: Into<CBOR> + TryFrom<CBOR, Error = dcbor::Error> + Sized {}

impl<T> QlCodec for T where T: Into<CBOR> + TryFrom<CBOR, Error = dcbor::Error> + Sized {}

pub trait RequestResponse: QlCodec {
    const ID: u64;
    type Response: QlCodec;
}

pub trait Event: QlCodec {
    const ID: u64;
}

#[derive(Debug, Clone)]
pub struct TypedPayload {
    pub message_id: u64,
    pub payload: CBOR,
}

impl From<TypedPayload> for CBOR {
    fn from(value: TypedPayload) -> Self {
        CBOR::from(vec![CBOR::from(value.message_id), value.payload])
    }
}

impl TryFrom<CBOR> for TypedPayload {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let mut array = value.try_into_array()?.into_iter();
        if array.len() != 2 {
            return Err(dcbor::Error::msg("invalid typed payload length"));
        }
        let message_id: u64 = array.next().unwrap().try_into()?;
        Ok(Self {
            message_id,
            payload: array.next().unwrap(),
        })
    }
}

#[derive(Debug)]
pub enum RouterError {
    Decode(dcbor::Error),
    MissingHandler(u64),
    Responded,
    Send(QlError),
}

impl From<dcbor::Error> for RouterError {
    fn from(error: dcbor::Error) -> Self {
        Self::Decode(error)
    }
}

impl From<QlError> for RouterError {
    fn from(error: QlError) -> Self {
        Self::Send(error)
    }
}

pub trait RouterPlatform {
    fn decrypt_payload(&self, payload: Envelope) -> Result<CBOR, RouterError>;
    fn encrypt_payload(&self, payload: CBOR, recipient: XID) -> Result<Envelope, RouterError>;
    fn signing_key(&self) -> SigningPublicKey;
    fn response_valid_for(&self) -> Duration;
    fn signer(&self) -> &dyn Signer;
    fn handle_error(&self, e: RouterError);
}

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

#[derive(Clone)]
pub struct TypedExecutorHandle {
    handle: ExecutorHandle,
    platform: Arc<dyn RouterPlatform>,
}

impl TypedExecutorHandle {
    pub fn new(handle: ExecutorHandle, platform: Arc<dyn RouterPlatform>) -> Self {
        Self { handle, platform }
    }

    pub fn handle(&self) -> &ExecutorHandle {
        &self.handle
    }

    pub async fn request<M>(
        &self,
        message: M,
        recipient: XID,
        request_config: RequestConfig,
        valid_for: Duration,
    ) -> Result<M::Response, RouterError>
    where
        M: RequestResponse,
    {
        let payload = TypedPayload {
            message_id: M::ID,
            payload: message.into(),
        };
        let encrypted = self.platform.encrypt_payload(payload.into(), recipient)?;
        let response = self
            .handle
            .request(
                encrypted,
                EncodeQlConfig {
                    signing_key: self.platform.signing_key(),
                    recipient,
                    valid_for,
                },
                request_config,
                self.platform.signer(),
            )
            .await?;
        let decrypted = self.platform.decrypt_payload(response.payload)?;
        let message = M::Response::try_from(decrypted)?;
        Ok(message)
    }

    pub async fn send_event<M>(
        &self,
        message: M,
        recipient: XID,
        valid_for: Duration,
    ) -> Result<(), RouterError>
    where
        M: Event,
    {
        let payload = TypedPayload {
            message_id: M::ID,
            payload: message.into(),
        };
        let encrypted = self.platform.encrypt_payload(payload.into(), recipient)?;
        self.handle
            .send_event(
                encrypted,
                EncodeQlConfig {
                    signing_key: self.platform.signing_key(),
                    recipient,
                    valid_for,
                },
                self.platform.signer(),
            )
            .await?;
        Ok(())
    }
}

impl<R> TypedResponder<R>
where
    R: QlCodec,
{
    pub fn respond(mut self, response: R) -> Result<(), RouterError> {
        self.respond_inner(response)
    }

    fn respond_inner(&mut self, response: R) -> Result<(), RouterError> {
        let responder = self.responder.take().ok_or(RouterError::Responded)?;
        let payload = response.into();
        let envelope = self.platform.encrypt_payload(payload, self.recipient)?;
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

    pub fn build(mut self, platform: Arc<dyn RouterPlatform>) -> Router<S> {
        self.handlers.shrink_to_fit();
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

pub type RouterHandler<S> =
    fn(&mut S, RouterEvent, Arc<dyn RouterPlatform>) -> Result<(), RouterError>;

pub enum RouterEvent {
    Event {
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
    pub fn message_id(&self) -> u64 {
        match self {
            RouterEvent::Event { payload, .. } => payload.message_id,
            RouterEvent::Request { payload, .. } => payload.message_id,
        }
    }
}

pub fn decrypt_event(
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

pub fn extract_typed_payload(
    platform: &dyn RouterPlatform,
    payload: Envelope,
) -> Result<TypedPayload, RouterError> {
    let decrypted = platform.decrypt_payload(payload)?;
    TypedPayload::try_from(decrypted).map_err(RouterError::Decode)
}
