use super::Route;
use crate::RpcCodec;

mod client;
mod server;

pub use self::{client::*, server::*};

/// rpc where both sides exchange typed events on the same stream
///
/// The initiator opens the routed stream. After that, either side may send any
/// number of events of its directional event type until it finishes or closes
/// its write side.
pub trait Duplex: Route {
    /// codec error shared by both directional event values
    type Error;
    /// typed event sent by the side that opened the stream
    type InitiatorEvent: RpcCodec<Error = Self::Error>;
    /// typed event sent by the side handling the route
    type ResponderEvent: RpcCodec<Error = Self::Error>;
}
