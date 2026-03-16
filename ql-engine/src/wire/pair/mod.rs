use bc_components::{MLDSAPublicKey, MLDSASignature, MLKEMCiphertext, MLKEMPublicKey};
use rkyv::{Archive, Deserialize, Serialize};

use super::{
    encrypted_message::EncryptedMessage, AsWireMlDsaPublicKey, AsWireMlDsaSignature,
    AsWireMlKemCiphertext, AsWireMlKemPublicKey, ControlMeta,
};

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PairRequestRecord {
    #[rkyv(with = AsWireMlKemCiphertext)]
    pub kem_ct: MLKEMCiphertext,
    pub encrypted: EncryptedMessage,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PairRequestBody {
    pub meta: ControlMeta,
    #[rkyv(with = AsWireMlDsaPublicKey)]
    pub signing_pub_key: MLDSAPublicKey,
    #[rkyv(with = AsWireMlKemPublicKey)]
    pub encapsulation_pub_key: MLKEMPublicKey,
    #[rkyv(with = AsWireMlDsaSignature)]
    pub proof: MLDSASignature,
}
