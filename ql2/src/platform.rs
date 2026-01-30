use std::{future::Future, pin::Pin, time::Duration};

use bc_components::{EncapsulationPrivateKey, Signer};

use crate::{runtime::PeerSession, QlError};

pub type PlatformFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub trait QlPlatform {
    fn signer(&self) -> &dyn Signer;
    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey;
    fn fill_bytes(&self, data: &mut [u8]);
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>>;
    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()>;
    fn handle_peer_status(&self, peer: bc_components::XID, session: &PeerSession);
}
