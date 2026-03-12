use std::{future::Future, pin::Pin, time::Duration};

use bc_components::{
    MLDSAPrivateKey, MLDSAPublicKey, MLKEMPrivateKey, MLKEMPublicKey, SigningPublicKey, XID,
};

use crate::{engine::PeerSession, Peer, QlError};

pub type PlatformFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub trait QlCrypto {
    fn signing_private_key(&self) -> &MLDSAPrivateKey;
    fn signing_public_key(&self) -> &MLDSAPublicKey;
    fn encapsulation_private_key(&self) -> &MLKEMPrivateKey;
    fn encapsulation_public_key(&self) -> &MLKEMPublicKey;

    fn fill_random_bytes(&self, data: &mut [u8]);

    fn xid(&self) -> XID {
        XID::new(SigningPublicKey::MLDSA(self.signing_public_key().clone()))
    }
}

pub trait QlPlatform: QlCrypto {
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>>;
    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()>;

    fn load_peer(&self) -> PlatformFuture<'_, Option<Peer>>;
    fn persist_peer(&self, peer: Peer);
    fn clear_peer(&self);

    fn handle_peer_status(&self, peer: XID, session: &PeerSession);
}
