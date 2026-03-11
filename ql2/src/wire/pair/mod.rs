use bc_components::{
    EncryptedMessage, MLDSAPublicKey, MLDSASignature, MLKEMCiphertext, MLKEMPublicKey,
};
use rkyv::{Archive, Serialize};

use super::{
    encrypted_message_from_archived, mldsa_public_key_from_archived, mldsa_signature_from_archived,
    mlkem_ciphertext_from_archived, mlkem_public_key_from_archived, AsWireEncryptedMessage,
    AsWireMlDsaPublicKey, AsWireMlDsaSignature, AsWireMlKemCiphertext, AsWireMlKemPublicKey,
};
use crate::{MessageId, QlError};

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Debug, Clone, PartialEq)]
pub struct PairRequestRecord {
    #[rkyv(with = AsWireMlKemCiphertext)]
    pub kem_ct: MLKEMCiphertext,
    #[rkyv(with = AsWireEncryptedMessage)]
    pub encrypted: EncryptedMessage,
}

impl TryFrom<&ArchivedPairRequestRecord> for PairRequestRecord {
    type Error = QlError;

    fn try_from(value: &ArchivedPairRequestRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            kem_ct: mlkem_ciphertext_from_archived(&value.kem_ct)?,
            encrypted: encrypted_message_from_archived(&value.encrypted),
        })
    }
}

impl TryFrom<&PairRequestRecord> for PairRequestRecord {
    type Error = QlError;

    fn try_from(value: &PairRequestRecord) -> Result<Self, Self::Error> {
        Ok(value.clone())
    }
}

#[derive(Archive, Serialize, Debug, Clone, PartialEq)]
pub struct PairRequestBody {
    pub message_id: MessageId,
    pub valid_until: u64,
    #[rkyv(with = AsWireMlDsaPublicKey)]
    pub signing_pub_key: MLDSAPublicKey,
    #[rkyv(with = AsWireMlKemPublicKey)]
    pub encapsulation_pub_key: MLKEMPublicKey,
    #[rkyv(with = AsWireMlDsaSignature)]
    pub proof: MLDSASignature,
}

impl TryFrom<&ArchivedPairRequestBody> for PairRequestBody {
    type Error = QlError;

    fn try_from(value: &ArchivedPairRequestBody) -> Result<Self, Self::Error> {
        Ok(Self {
            message_id: (&value.message_id).into(),
            valid_until: value.valid_until.to_native(),
            signing_pub_key: mldsa_public_key_from_archived(&value.signing_pub_key)?,
            encapsulation_pub_key: mlkem_public_key_from_archived(&value.encapsulation_pub_key)?,
            proof: mldsa_signature_from_archived(&value.proof)?,
        })
    }
}
