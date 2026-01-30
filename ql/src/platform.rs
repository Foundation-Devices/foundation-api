use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use bc_components::{
    EncapsulationCiphertext, EncapsulationPrivateKey, EncapsulationPublicKey, Signer,
    SigningPublicKey, SymmetricKey, XID,
};
use dcbor::CBOR;

use crate::{MessageId, QlError, SessionEpoch};

pub type PlatformFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

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
        session_epoch: SessionEpoch,
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

pub trait QlPeer {
    fn encapsulation_pub_key(&self) -> &EncapsulationPublicKey;
    fn signing_pub_key(&self) -> &SigningPublicKey;
    fn session(&self) -> Option<SymmetricKey>;
    fn session_epoch(&self) -> Option<SessionEpoch>;
    fn store_session_key(&self, key: SymmetricKey);
    fn set_session_epoch(&self, epoch: Option<SessionEpoch>);
    fn pending_session(&self) -> Option<PendingSession>;
    fn set_pending_session(&self, handshake: Option<PendingSession>);
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

    fn session_epoch(&self) -> Option<SessionEpoch> {
        (**self).session_epoch()
    }

    fn store_session_key(&self, key: SymmetricKey) {
        (**self).store_session_key(key)
    }

    fn set_session_epoch(&self, epoch: Option<SessionEpoch>) {
        (**self).set_session_epoch(epoch)
    }

    fn pending_session(&self) -> Option<PendingSession> {
        (**self).pending_session()
    }

    fn set_pending_session(&self, handshake: Option<PendingSession>) {
        (**self).set_pending_session(handshake)
    }
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
pub enum SessionKind {
    SessionInit,
    SessionReset,
}

#[derive(Debug, Clone, Copy)]
pub struct PendingSession {
    pub kind: SessionKind,
    pub origin: ResetOrigin,
    pub id: MessageId,
    pub epoch: SessionEpoch,
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
        payload: &bc_components::EncryptedMessage,
    ) -> Result<CBOR, QlError> {
        if payload.aad() != header_aad {
            return Err(QlError::InvalidPayload);
        }
        let plaintext = key.decrypt(payload).map_err(|_| QlError::InvalidPayload)?;
        Ok(CBOR::try_from_data(plaintext)?)
    }
}

impl<T> QlPlatformExt for T where T: QlPlatform {}
