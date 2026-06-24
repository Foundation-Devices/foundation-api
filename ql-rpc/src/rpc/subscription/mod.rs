use super::Route;
use crate::RpcCodec;

pub(crate) mod client;
pub(crate) mod codec;
pub(crate) mod server;

pub use client::{start, SubscriptionCall};
pub use server::{SubscriptionHandler, SubscriptionHandlerLocal, SubscriptionResponder};

/// rpc where one request opens a stream of typed events
///
/// event frames are length-delimited and the stream ends cleanly at eof
/// any partial trailing frame is reported as truncation on the client side
pub trait Subscription: Route {
    /// codec error shared by request and event values
    type Error;
    /// typed input that starts the subscription
    type Request: RpcCodec<Error = Self::Error>;
    /// typed event yielded by the responder
    type Event: RpcCodec<Error = Self::Error>;
}
