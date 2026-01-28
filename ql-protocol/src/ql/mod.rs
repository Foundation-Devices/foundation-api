use std::{sync::Arc, time::Duration};

use bc_components::{
    EncapsulationCiphertext, EncapsulationPrivateKey, EncapsulationPublicKey, EncryptedMessage,
    Signer, SigningPublicKey, SymmetricKey, ARID, XID,
};
use dcbor::CBOR;

use crate::{cbor::cbor_array, ExecutorError};

pub(crate) mod encrypt;
pub mod handle;
pub mod router;

pub trait QlCodec: Into<CBOR> + TryFrom<CBOR, Error = dcbor::Error> {}

impl<T> QlCodec for T where T: Into<CBOR> + TryFrom<CBOR, Error = dcbor::Error> {}

pub trait RequestResponse: QlCodec {
    const ID: u64;
    type Response: QlCodec;
}

pub trait Event: QlCodec {
    const ID: u64;
}

#[derive(Debug, Clone)]
pub struct QlPayload {
    pub message_id: u64,
    pub payload: CBOR,
}

impl From<QlPayload> for CBOR {
    fn from(value: QlPayload) -> Self {
        CBOR::from(vec![CBOR::from(value.message_id), value.payload])
    }
}

impl TryFrom<CBOR> for QlPayload {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        let [message_id, payload] = cbor_array::<2>(array)?;
        let message_id = message_id.try_into()?;
        Ok(Self {
            message_id,
            payload,
        })
    }
}

#[derive(Debug)]
pub enum QlError {
    Decode(dcbor::Error),
    Expired,
    InvalidPayload,
    InvalidSignature,
    MissingHandler(u64),
    MissingSession(XID),
    SessionInitCollision,
    Send(ExecutorError),
    UnknownPeer(XID),
}

impl From<dcbor::Error> for QlError {
    fn from(error: dcbor::Error) -> Self {
        Self::Decode(error)
    }
}

impl From<ExecutorError> for QlError {
    fn from(error: ExecutorError) -> Self {
        Self::Send(error)
    }
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
    type Peer: QlPeer;

    fn lookup_peer(&self, peer: XID) -> Option<Self::Peer>;
    fn lookup_peer_or_fail(&self, peer: XID) -> Result<Self::Peer, QlError> {
        self.lookup_peer(peer)
            .ok_or_else(|| QlError::UnknownPeer(peer))
    }

    fn store_peer(
        &self,
        signing_pub_key: SigningPublicKey,
        encapsulation_pub_key: EncapsulationPublicKey,
        session: SymmetricKey,
    );

    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey;
    fn encapsulation_public_key(&self) -> EncapsulationPublicKey;
    fn signing_key(&self) -> &SigningPublicKey;
    fn message_expiration(&self) -> Duration;
    fn signer(&self) -> &dyn Signer;
    fn handle_error(&self, e: QlError);

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

pub use handle::QlExecutorHandle;
pub use router::{EventHandler, QlRequest, QlResponder, RequestHandler, Router, RouterBuilder};

#[cfg(test)]
mod test;
