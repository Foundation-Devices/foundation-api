use std::{future::Future, pin::Pin, time::Duration};

use bc_components::{
    MLDSAPrivateKey, MLDSAPublicKey, MLKEMPrivateKey, MLKEMPublicKey, SigningPublicKey, XID,
};

use crate::{engine::PeerSession, Peer, QlError};

pub type PlatformFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[derive(Debug, Clone)]
pub struct QlIdentity {
    pub xid: XID,
    pub signing_private_key: MLDSAPrivateKey,
    pub signing_public_key: MLDSAPublicKey,
    pub encapsulation_private_key: MLKEMPrivateKey,
    pub encapsulation_public_key: MLKEMPublicKey,
}

impl QlIdentity {
    pub fn from_keys(
        signing_private_key: MLDSAPrivateKey,
        signing_public_key: MLDSAPublicKey,
        encapsulation_private_key: MLKEMPrivateKey,
        encapsulation_public_key: MLKEMPublicKey,
    ) -> Self {
        Self {
            xid: XID::new(SigningPublicKey::MLDSA(signing_public_key.clone())),
            signing_private_key,
            signing_public_key,
            encapsulation_private_key,
            encapsulation_public_key,
        }
    }
}

pub trait QlCrypto {
    fn fill_random_bytes(&self, data: &mut [u8]);
}

pub trait QlPlatform: QlCrypto {
    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>>;
    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()>;

    fn load_peer(&self) -> PlatformFuture<'_, Option<Peer>>;
    fn persist_peer(&self, peer: Peer);
    fn clear_peer(&self);

    fn handle_peer_status(&self, peer: XID, session: &PeerSession);
    fn handle_inbound(&self, event: crate::runtime::HandlerEvent);
}
