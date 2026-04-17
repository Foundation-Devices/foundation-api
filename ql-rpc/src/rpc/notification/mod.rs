use crate::{RouteId, RpcCodec};

pub(crate) mod codec;

pub use codec::encode_notification;

pub trait Notification {
    const ROUTE: RouteId;
    type Error;
    type Payload: RpcCodec<Error = Self::Error>;
}
