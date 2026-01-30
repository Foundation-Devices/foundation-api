use std::{future::Future, pin::Pin, time::Duration};

use bc_components::{EncapsulationPrivateKey, Signer, SigningPublicKey, XID};

use crate::{runtime::PeerSession, QlError};

pub type PlatformFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub trait QlPlatform {
    fn signer(&self) -> &dyn Signer;
    fn signing_public_key(&self) -> &SigningPublicKey;
    fn encapsulation_private_key(&self) -> &EncapsulationPrivateKey;

    fn fill_bytes(&self, data: &mut [u8]);
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>>;
    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()>;
    fn handle_peer_status(&self, peer: XID, session: &PeerSession);
}

pub(crate) trait QlPlatformExt: QlPlatform {
    fn xid(&self) -> XID {
        XID::new(&self.signing_public_key())
    }
}

impl<T: QlPlatform> QlPlatformExt for T {}
