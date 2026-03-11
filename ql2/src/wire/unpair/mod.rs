use bc_components::MLDSASignature;
use rkyv::{Archive, Serialize};

use super::{mldsa_signature_from_archived, AsWireMlDsaSignature};
use crate::{MessageId, QlError};

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Debug, Clone, PartialEq)]
pub struct UnpairRecord {
    pub message_id: MessageId,
    pub valid_until: u64,
    #[rkyv(with = AsWireMlDsaSignature)]
    pub signature: MLDSASignature,
}

impl TryFrom<&ArchivedUnpairRecord> for UnpairRecord {
    type Error = QlError;

    fn try_from(value: &ArchivedUnpairRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            message_id: (&value.message_id).into(),
            valid_until: value.valid_until.to_native(),
            signature: mldsa_signature_from_archived(&value.signature)?,
        })
    }
}

impl TryFrom<&UnpairRecord> for UnpairRecord {
    type Error = QlError;

    fn try_from(value: &UnpairRecord) -> Result<Self, Self::Error> {
        Ok(value.clone())
    }
}
