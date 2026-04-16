use crate::{RouteId, RpcCodec};

pub(crate) mod codec;

pub use codec::encode_event;

pub trait Notification {
    const ROUTE: RouteId;
    type Error;
    type Event: RpcCodec<Error = Self::Error>;
}
