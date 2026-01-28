use std::time::Duration;

use bc_components::{
    EncapsulationCiphertext, EncapsulationPrivateKey, EncapsulationPublicKey, EncryptedMessage,
    Signer, SigningPublicKey, SymmetricKey, XID,
};
use dcbor::CBOR;

use crate::QlError;

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
pub struct TypedPayload {
    pub message_id: u64,
    pub payload: CBOR,
}

impl From<TypedPayload> for CBOR {
    fn from(value: TypedPayload) -> Self {
        CBOR::from(vec![CBOR::from(value.message_id), value.payload])
    }
}

impl TryFrom<CBOR> for TypedPayload {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        if array.len() != 2 {
            return Err(dcbor::Error::msg("invalid typed payload length"));
        }
        let message_id: u64 = array[0].clone().try_into()?;
        Ok(Self {
            message_id,
            payload: array[1].clone(),
        })
    }
}

#[derive(Debug)]
pub enum RouterError {
    Decode(dcbor::Error),
    InvalidPayload,
    InvalidSignature,
    MissingHandler(u64),
    MissingSession(XID),
    Send(QlError),
    UnknownRecipient(XID),
    UnknownSender(XID),
}

impl From<dcbor::Error> for RouterError {
    fn from(error: dcbor::Error) -> Self {
        Self::Decode(error)
    }
}

impl From<QlError> for RouterError {
    fn from(error: QlError) -> Self {
        Self::Send(error)
    }
}

pub trait RouterPlatform {
    fn lookup_recipient(&self, recipient: XID) -> Option<&EncapsulationPublicKey>;
    fn lookup_signing_key(&self, sender: XID) -> Option<&SigningPublicKey>;
    fn session_for_peer(&self, peer: XID) -> Option<SymmetricKey>;
    fn store_session(&self, peer: XID, key: SymmetricKey);
    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey;
    fn signing_key(&self) -> &SigningPublicKey;
    fn message_expiration(&self) -> Duration;
    fn signer(&self) -> &dyn Signer;
    fn handle_error(&self, e: RouterError);

    fn sender_xid(&self) -> XID {
        XID::new(self.signing_key())
    }

    fn decapsulate_shared_secret(
        &self,
        ciphertext: &EncapsulationCiphertext,
    ) -> Result<SymmetricKey, RouterError> {
        self.encapsulation_private_key()
            .decapsulate_shared_secret(ciphertext)
            .map_err(|_| RouterError::InvalidPayload)
    }

    fn decrypt_message(
        &self,
        key: &SymmetricKey,
        header_aad: &[u8],
        payload: &EncryptedMessage,
    ) -> Result<CBOR, RouterError> {
        if payload.aad() != header_aad {
            return Err(RouterError::InvalidPayload);
        }
        let plaintext = key
            .decrypt(payload)
            .map_err(|_| RouterError::InvalidPayload)?;
        Ok(CBOR::try_from_data(plaintext)?)
    }
}

pub use handle::TypedExecutorHandle;
pub use router::{
    EventHandler, RequestHandler, Router, RouterBuilder, TypedRequest, TypedResponder,
};

#[cfg(test)]
mod test;
