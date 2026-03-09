use bc_components::MLDSASignature;
use dcbor::CBOR;

use super::take_fields;
use crate::MessageId;

mod crypto;
pub use crypto::*;

#[derive(Debug, Clone, PartialEq)]
pub struct UnpairRecord {
    pub message_id: MessageId,
    pub valid_until: u64,
    pub signature: MLDSASignature,
}

impl From<UnpairRecord> for CBOR {
    fn from(value: UnpairRecord) -> Self {
        CBOR::from(vec![
            CBOR::from(value.message_id),
            CBOR::from(value.valid_until),
            CBOR::from(value.signature),
        ])
    }
}

impl TryFrom<CBOR> for UnpairRecord {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let iter = value.try_into_array()?.into_iter();
        let [message_id, valid_until, signature] = take_fields(iter)?;
        Ok(Self {
            message_id: message_id.try_into()?,
            valid_until: valid_until.try_into()?,
            signature: signature.try_into()?,
        })
    }
}
