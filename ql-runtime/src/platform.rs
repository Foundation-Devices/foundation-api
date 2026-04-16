use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use ql_fsm::{PeerStatus, ReceiveError};
use ql_wire::{PeerBundle, QlCrypto, XID};

use crate::QlStream;

pub type PlatformFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub trait QlTimer {
    fn set_deadline(self: Pin<&mut Self>, deadline: Option<Instant>);
    fn poll_wait(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()>;
}

pub trait QlInbound {
    fn poll_recv(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Vec<u8>>;
}

pub trait QlPlatform: QlCrypto {
    type Timer: QlTimer;
    type WriteMessageFut<'a>: Future<Output = bool> + Unpin + 'a
    where
        Self: 'a;
    type Inbound: QlInbound;

    fn write_message(&self, message: Vec<u8>) -> Self::WriteMessageFut<'_>;
    /// Returns the platform's inbound transport poller.
    ///
    /// The runtime calls this once while starting the driver loop and retains the returned
    /// poller for the lifetime of the runtime. Platform implementations may panic if this is
    /// called more than once.
    fn inbound(&mut self) -> Self::Inbound;
    fn timer(&self) -> Self::Timer;

    fn persist_peer(&self, peer: PeerBundle);

    fn handle_peer_status(&self, peer: XID, status: PeerStatus);
    fn handle_inbound(&self, event: QlStream);
    fn handle_recv_error(&self, _error: ReceiveError) {}
}
