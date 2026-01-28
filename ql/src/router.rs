use std::collections::HashMap;

use thiserror::Error;

use crate::{
    runtime::{HandlerEvent, Responder, RuntimeError},
    wire::Nack,
    Event, QlCodec, RequestResponse,
};

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
    default: fn() -> R,
}

impl<R> QlResponder<R>
where
    R: QlCodec,
{
    pub fn respond(mut self, response: R) -> Result<(), RuntimeError> {
        self.respond_inner(response)
    }

    pub fn respond_nack(mut self, reason: Nack) -> Result<(), RuntimeError> {
        let responder = self.responder.take().unwrap();
        responder.respond_nack(reason)
    }

    fn respond_inner(&mut self, response: R) -> Result<(), RuntimeError> {
        let responder = self.responder.take().unwrap();
        responder.respond(response)
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

#[derive(Debug, Error)]
pub enum RouterError {
    #[error(transparent)]
    Decode(#[from] dcbor::Error),
    #[error("missing handler {0}")]
    MissingHandler(u64),
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
}

type RouterHandler<S> = fn(&mut S, HandlerEvent) -> Result<(), RouterError>;

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

    pub fn build(mut self, state: S) -> Router<S> {
        self.handlers.shrink_to_fit();
        Router {
            handlers: self.handlers,
            state,
        }
    }

    fn add_handler(mut self, id: u64, handler: RouterHandler<S>) -> Self {
        if self.handlers.insert(id, handler).is_some() {
            panic!("duplicate message_id {id}");
        }
        self
    }
}

pub struct Router<S> {
    state: S,
    handlers: HashMap<u64, RouterHandler<S>>,
}

impl<S> Router<S> {
    pub fn builder() -> RouterBuilder<S> {
        RouterBuilder::new()
    }

    pub fn handle(&mut self, event: HandlerEvent) -> Result<(), RouterError> {
        match event {
            HandlerEvent::Request(request) => {
                let message_id = request.message.payload.message_id;
                let handler = match self.handlers.get(&message_id) {
                    Some(handler) => handler,
                    None => {
                        let _ = request.respond_to.respond_nack(Nack::UnknownMessage);
                        return Ok(());
                    }
                };
                handler(&mut self.state, HandlerEvent::Request(request))
            }
            HandlerEvent::Event(event) => {
                let message_id = event.message.payload.message_id;
                let handler = self
                    .handlers
                    .get(&message_id)
                    .ok_or(RouterError::MissingHandler(message_id))?;
                handler(&mut self.state, HandlerEvent::Event(event))
            }
        }
    }
}

fn handle_request<M, S>(state: &mut S, event: HandlerEvent) -> Result<(), RouterError>
where
    M: RequestResponse,
    S: RequestHandler<M>,
{
    let (payload, responder) = match event {
        HandlerEvent::Request(request) => (request.message.payload, request.respond_to),
        HandlerEvent::Event(_) => unreachable!("expected request"),
    };
    let message = match M::try_from(payload.payload) {
        Ok(message) => message,
        Err(error) => {
            let _ = responder.respond_nack(Nack::InvalidPayload);
            return Err(RouterError::Decode(error));
        }
    };
    let responder = QlResponder {
        responder: Some(responder),
        default: S::default_response,
    };
    state.handle(QlRequest { message, responder });
    Ok(())
}

fn handle_event<M, S>(state: &mut S, event: HandlerEvent) -> Result<(), RouterError>
where
    M: Event,
    S: EventHandler<M>,
{
    let payload = match event {
        HandlerEvent::Event(event) => event.message.payload,
        HandlerEvent::Request(_) => unreachable!("expected event"),
    };
    let message = M::try_from(payload.payload)?;
    state.handle(message);
    Ok(())
}
