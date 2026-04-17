use crate::{RouteId, RpcCodec};

pub(crate) mod client;
pub(crate) mod server;

pub use client::encode_notification;
pub use server::NotificationHandler;

pub trait Notification {
    const ROUTE: RouteId;
    type Error;
    type Payload: RpcCodec<Error = Self::Error>;
}
