use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use ql_fsm::PeerStatus;
use ql_wire::{PairingToken, PeerBundle, QlCrypto, XID};

use crate::QlStream;

pub type PlatformFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub trait QlTimer {
    fn set_deadline(&mut self, deadline: Option<Instant>);
    fn poll_wait(&mut self, cx: &mut Context<'_>) -> Poll<()>;
}

pub trait QlPlatform: QlCrypto {
    type Timer: QlTimer;
    type WriteMessageFut<'a>: Future<Output = bool> + Unpin + 'a
    where
        Self: 'a;
    type PairingDecisionFut<'a>: Future<Output = bool> + Unpin + 'a
    where
        Self: 'a;

    fn write_message(&self, message: Vec<u8>) -> Self::WriteMessageFut<'_>;
    fn timer(&self) -> Self::Timer;

    fn load_peer(&self) -> PlatformFuture<'_, Option<PeerBundle>>;
    fn persist_peer(&self, peer: PeerBundle);

    fn handle_peer_status(&self, peer: XID, status: PeerStatus);
    fn handle_pairing_request(
        &self,
        token: PairingToken,
        peer: PeerBundle,
    ) -> Self::PairingDecisionFut<'_>;
    fn handle_inbound(&self, event: QlStream);
}
