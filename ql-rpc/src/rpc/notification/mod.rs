use super::Route;
use crate::RpcCodec;

pub(crate) mod client;
pub(crate) mod server;

pub use client::send;
pub use server::{NotificationHandler, NotificationHandlerLocal};

/// one-way rpc that carries a single typed payload and no typed response
///
/// the server reads [`Self::Payload`] to eof and then closes the response side
/// of the stream
pub trait Notification: Route {
    /// codec error for the notification payload
    type Error;
    /// typed payload emitted by the caller
    type Payload: RpcCodec<Error = Self::Error>;
}
