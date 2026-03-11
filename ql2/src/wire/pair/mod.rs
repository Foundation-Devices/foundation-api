use bc_components::{
    EncryptedMessage, MLDSAPublicKey, MLDSASignature, MLKEMCiphertext, MLKEMPublicKey,
};
use rkyv::{Archive, Deserialize, Serialize};

use super::{
    AsWireEncryptedMessage, AsWireMlDsaPublicKey, AsWireMlDsaSignature, AsWireMlKemCiphertext,
    AsWireMlKemPublicKey,
};
use crate::MessageId;

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
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
