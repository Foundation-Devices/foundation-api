use crate::{RouteId, RpcCodec};

pub(crate) mod client;
pub(crate) mod server;

pub use client::encode_notification;
pub use server::NotificationHandler;

/// one-way rpc that carries a single typed payload and no typed response
///
/// the server reads [`Self::Payload`] to eof and then closes the response side
/// of the stream
pub trait Notification {
    /// route used to dispatch this notification
    const ROUTE: RouteId;
    /// codec error for the notification payload
    type Error;
    /// typed payload emitted by the caller
    type Payload: RpcCodec<Error = Self::Error>;
}
