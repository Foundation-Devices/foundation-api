use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use bc_components::{
    EncapsulationCiphertext, EncapsulationPrivateKey, EncapsulationPublicKey, EncryptedMessage,
    Signer, SigningPublicKey, SymmetricKey, ARID, XID,
};
use dcbor::CBOR;

use crate::QlError;

pub type PlatformFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub trait QlPeer {
    fn encapsulation_pub_key(&self) -> &EncapsulationPublicKey;
    fn signing_pub_key(&self) -> &SigningPublicKey;
    fn session(&self) -> Option<SymmetricKey>;
    fn store_session(&self, key: SymmetricKey);
    fn pending_handshake(&self) -> Option<PendingHandshake>;
    fn set_pending_handshake(&self, handshake: Option<PendingHandshake>);
}

impl<T> QlPeer for Arc<T>
where
    T: QlPeer + ?Sized,
{
    fn encapsulation_pub_key(&self) -> &EncapsulationPublicKey {
        (**self).encapsulation_pub_key()
    }

    fn signing_pub_key(&self) -> &SigningPublicKey {
        (**self).signing_pub_key()
    }

    fn session(&self) -> Option<SymmetricKey> {
        (**self).session()
    }

    fn store_session(&self, key: SymmetricKey) {
        (**self).store_session(key)
    }

    fn pending_handshake(&self) -> Option<PendingHandshake> {
        (**self).pending_handshake()
    }

    fn set_pending_handshake(&self, handshake: Option<PendingHandshake>) {
        (**self).set_pending_handshake(handshake)
    }
}

pub trait QlPlatform {
    type Peer<'a>: QlPeer + 'a
    where
        Self: 'a;

    fn lookup_peer(&self, peer: XID) -> Option<Self::Peer<'_>>;
    fn store_peer(
        &self,
        signing_pub_key: SigningPublicKey,
        encapsulation_pub_key: EncapsulationPublicKey,
        session: SymmetricKey,
    );

    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey;
    fn encapsulation_public_key(&self) -> EncapsulationPublicKey;
    fn signing_key(&self) -> &SigningPublicKey;
    fn signer(&self) -> &dyn Signer;

    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), QlError>>;
    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()>;
    fn handle_error(&self, e: QlError);
    fn handle_peer_status(&self, peer: XID, status: PeerStatus);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    Connecting,
    Connected,
    HeartbeatPending,
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetOrigin {
    Local,
    Peer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeKind {
    SessionInit,
    SessionReset,
}

#[derive(Debug, Clone, Copy)]
pub struct PendingHandshake {
    pub kind: HandshakeKind,
    pub origin: ResetOrigin,
    pub id: ARID,
}

pub(crate) trait QlPlatformExt: QlPlatform {
    fn lookup_peer_or_fail(&self, peer: XID) -> Result<Self::Peer<'_>, QlError> {
        self.lookup_peer(peer)
            .ok_or_else(|| QlError::UnknownPeer(peer))
    }

    fn xid(&self) -> XID {
        XID::new(self.signing_key())
    }

    fn decapsulate_shared_secret(
        &self,
        ciphertext: &EncapsulationCiphertext,
    ) -> Result<SymmetricKey, QlError> {
        self.encapsulation_private_key()
            .decapsulate_shared_secret(ciphertext)
            .map_err(|_| QlError::InvalidPayload)
    }

    fn decrypt_message(
        &self,
        key: &SymmetricKey,
        header_aad: &[u8],
        payload: &EncryptedMessage,
    ) -> Result<CBOR, QlError> {
        if payload.aad() != header_aad {
            return Err(QlError::InvalidPayload);
        }
        let plaintext = key.decrypt(payload).map_err(|_| QlError::InvalidPayload)?;
        Ok(CBOR::try_from_data(plaintext)?)
    }
}

impl<T> QlPlatformExt for T where T: QlPlatform {}
