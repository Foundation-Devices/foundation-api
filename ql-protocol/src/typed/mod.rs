use std::time::Duration;

use bc_components::{EncapsulationPublicKey, Signer, SigningPublicKey, XID};
use bc_envelope::Envelope;
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
    MissingHandler(u64),
    Send(QlError),
    UnknownRecipient(XID),
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
    fn decrypt_payload(&self, payload: Envelope) -> Result<CBOR, RouterError>;
    fn lookup_recipient(&self, recipient: XID) -> Option<&EncapsulationPublicKey>;
    fn signing_key(&self) -> &SigningPublicKey;
    fn response_valid_for(&self) -> Duration;
    fn signer(&self) -> &dyn Signer;
    fn handle_error(&self, e: RouterError);

    fn encrypt_payload_or_fail(
        &self,
        recipient: XID,
        payload: CBOR,
    ) -> Result<Envelope, RouterError> {
        let pubkey = self
            .lookup_recipient(recipient)
            .ok_or_else(|| RouterError::UnknownRecipient(recipient))?;
        Ok(Envelope::new(payload).encrypt_to_recipient(pubkey))
    }
}

pub use handle::TypedExecutorHandle;
pub use router::{
    EventHandler, RequestHandler, Router, RouterBuilder, TypedRequest, TypedResponder,
};

#[cfg(test)]
mod test;
