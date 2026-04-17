use crate::{RouteId, RpcCodec};

pub(crate) mod client;
pub(crate) mod codec;
pub(crate) mod server;

pub use client::SubscriptionCall;
pub use codec::{encode_item, encode_request, ReadStep, ResponseReader};
pub use server::{SubscriptionHandler, SubscriptionResponder};

/// rpc where one request opens a stream of typed events
///
/// event frames are length-delimited and the stream ends cleanly at eof
/// any partial trailing frame is reported as truncation on the client side
pub trait Subscription {
    /// route used to dispatch this rpc family
    const ROUTE: RouteId;
    /// codec error shared by request and event values
    type Error;
    /// typed input that starts the subscription
    type Request: RpcCodec<Error = Self::Error>;
    /// typed event yielded by the responder
    type Event: RpcCodec<Error = Self::Error>;
}
