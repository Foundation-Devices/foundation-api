use bc_components::{MLDSAPublicKey, MLDSASignature, MLKEMCiphertext, Nonce};
use rkyv::{Archive, Deserialize, Serialize};

use super::{AsWireMlDsaSignature, AsWireMlKemCiphertext, AsWireNonce};
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
    #[rkyv(with = AsWireNonce)]
    pub nonce: Nonce,
    #[rkyv(with = AsWireMlKemCiphertext)]
    pub kem_ct: MLKEMCiphertext,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HelloReply {
    #[rkyv(with = AsWireNonce)]
    pub nonce: Nonce,
    #[rkyv(with = AsWireMlKemCiphertext)]
    pub kem_ct: MLKEMCiphertext,
    #[rkyv(with = AsWireMlDsaSignature)]
    pub signature: MLDSASignature,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Confirm {
    #[rkyv(with = AsWireMlDsaSignature)]
    pub signature: MLDSASignature,
}

pub fn verify_transcript_signature(
    signing_key: &MLDSAPublicKey,
    signature: &MLDSASignature,
    transcript: &[u8],
) -> Result<(), QlError> {
    match signing_key.verify(signature, transcript) {
        Ok(true) => Ok(()),
        _ => Err(QlError::InvalidSignature),
    }
}
