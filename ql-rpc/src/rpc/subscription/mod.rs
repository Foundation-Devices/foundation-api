use crate::{RouteId, RpcCodec};

pub(crate) mod client;
pub(crate) mod codec;
pub(crate) mod server;

pub use client::SubscriptionCall;
pub use codec::{encode_item, encode_request, ReadStep, ResponseReader};
pub use server::{SubscriptionHandler, SubscriptionResponder};

pub trait Subscription {
    const ROUTE: RouteId;
    type Error;
    type Request: RpcCodec<Error = Self::Error>;
    type Event: RpcCodec<Error = Self::Error>;
}
