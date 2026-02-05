use std::{future::Future, pin::Pin, time::Duration};

use bc_components::{
    MLDSAPrivateKey, MLDSAPublicKey, MLKEMPrivateKey, MLKEMPublicKey, SigningPublicKey, XID,
};

use crate::{
    runtime::{HandlerEvent, PeerSession},
    QlError,
};

pub type PlatformFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub trait QlPlatform {
    fn signing_private_key(&self) -> &MLDSAPrivateKey;
    fn signing_public_key(&self) -> &MLDSAPublicKey;
    fn encapsulation_private_key(&self) -> &MLKEMPrivateKey;
    fn encapsulation_public_key(&self) -> &MLKEMPublicKey;

    fn fill_random_bytes(&self, data: &mut [u8]);
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>>;
    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()>;
    fn handle_peer_status(&self, peer: XID, session: &PeerSession);
    fn handle_inbound(&self, event: HandlerEvent);
}

pub(crate) trait QlPlatformExt: QlPlatform {
    fn xid(&self) -> XID {
        XID::new(SigningPublicKey::MLDSA(self.signing_public_key().clone()))
    }
}

impl<T: QlPlatform> QlPlatformExt for T {}
