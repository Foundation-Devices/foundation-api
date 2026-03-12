use bc_components::{MLDSAPublicKey, MLDSASignature, MLKEMCiphertext, Nonce};
use rkyv::{Archive, Deserialize, Serialize};

use super::{AsWireMlDsaSignature, AsWireMlKemCiphertext, AsWireNonce, ControlMeta};
use crate::QlError;

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum HandshakeRecord {
    Hello(Hello),
    HelloReply(HelloReply),
    Confirm(Confirm),
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Hello {
    pub meta: ControlMeta,
    #[rkyv(with = AsWireNonce)]
    pub nonce: Nonce,
    #[rkyv(with = AsWireMlKemCiphertext)]
    pub kem_ct: MLKEMCiphertext,
    #[rkyv(with = AsWireMlDsaSignature)]
    pub signature: MLDSASignature,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HelloReply {
    pub meta: ControlMeta,
    #[rkyv(with = AsWireNonce)]
    pub nonce: Nonce,
    #[rkyv(with = AsWireMlKemCiphertext)]
    pub kem_ct: MLKEMCiphertext,
    #[rkyv(with = AsWireMlDsaSignature)]
    pub signature: MLDSASignature,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Confirm {
    pub meta: ControlMeta,
    #[rkyv(with = AsWireMlDsaSignature)]
    pub signature: MLDSASignature,
}

pub fn verify_signature(
    signing_key: &MLDSAPublicKey,
    signature: &MLDSASignature,
    proof_data: &[u8],
) -> Result<(), QlError> {
    match signing_key.verify(signature, proof_data) {
        Ok(true) => Ok(()),
        _ => Err(QlError::InvalidSignature),
    }
}
