use bc_components::{
    EncryptedMessage, MLDSAPublicKey, MLDSASignature, MLKEMCiphertext, MLKEMPublicKey,
};
use rkyv::{Archive, Deserialize, Serialize};

use super::{
    encrypted_message_from_archived, mlkem_ciphertext_from_archived, AsWireEncryptedMessage,
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

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
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

pub(crate) fn decode_pair_request_record(
    header: &super::QlHeader,
    value: &ArchivedPairRequestRecord,
) -> Result<PairRequestRecord, QlError> {
    let kem_ct = mlkem_ciphertext_from_archived(&value.kem_ct)?;
    let aad = crypto::pairing_aad(header, &kem_ct);
    Ok(PairRequestRecord {
        kem_ct,
        encrypted: encrypted_message_from_archived(&value.encrypted, &aad),
    })
}
