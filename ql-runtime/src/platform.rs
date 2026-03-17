use std::{future::Future, pin::Pin, time::Duration};

use ql_wire::QlCrypto;

use crate::{Peer, PeerStatus, QlError, XID};

pub type PlatformFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub trait QlPlatform: QlCrypto {
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>>;
    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()>;

    fn load_peer(&self) -> PlatformFuture<'_, Option<Peer>>;
    fn persist_peer(&self, peer: Peer);
    fn clear_peer(&self);

    fn handle_peer_status(&self, peer: XID, status: PeerStatus);
    fn handle_inbound(&self, event: super::HandlerEvent);
}
