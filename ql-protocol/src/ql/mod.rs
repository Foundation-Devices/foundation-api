use std::time::Duration;

use bc_components::{
    EncapsulationCiphertext, EncapsulationPrivateKey, EncapsulationPublicKey, EncryptedMessage,
    Signer, SigningPublicKey, SymmetricKey, XID,
};
use dcbor::CBOR;

use crate::{cbor::cbor_array, ExecutorError};

pub mod handle;
pub mod router;

pub trait QlCodec: Into<CBOR> + TryFrom<CBOR, Error = dcbor::Error> + Sized {}

impl<T> QlCodec for T where T: Into<CBOR> + TryFrom<CBOR, Error = dcbor::Error> + Sized {}

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
    InvalidPayload,
    InvalidSignature,
    MissingHandler(u64),
    MissingSession(XID),
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

pub trait QlPeer {
    fn encapsulation_pub_key(&self) -> &EncapsulationPublicKey;
    fn signing_pub_key(&self) -> &SigningPublicKey;
    fn session(&self) -> Option<SymmetricKey>;
    fn store_session(&self, key: SymmetricKey);
}

pub trait QlPlatform {
    fn lookup_peer(&self, peer: XID) -> Option<&dyn QlPeer>;
    fn lookup_peer_or_fail(&self, peer: XID) -> Result<&dyn QlPeer, QlError> {
        self.lookup_peer(peer)
            .ok_or_else(|| QlError::UnknownPeer(peer))
    }

    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey;
    fn signing_key(&self) -> &SigningPublicKey;
    fn message_expiration(&self) -> Duration;
    fn signer(&self) -> &dyn Signer;
    fn handle_error(&self, e: QlError);

    fn sender_xid(&self) -> XID {
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
