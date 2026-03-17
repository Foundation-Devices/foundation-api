use rkyv::{Archive, Deserialize, Serialize};

use crate::{
    encrypted_message::EncryptedMessage, ControlMeta, MlDsaPublicKey, MlDsaSignature,
    MlKemCiphertext, Nonce, WireError,
};

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum HandshakeRecord {
    Hello(Hello),
    HelloReply(HelloReply),
    Confirm(Confirm),
    Ready(Ready),
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Hello {
    pub meta: ControlMeta,
    pub nonce: Nonce,
    pub kem_ct: MlKemCiphertext,
    pub signature: MlDsaSignature,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HelloReply {
    pub meta: ControlMeta,
    pub nonce: Nonce,
    pub kem_ct: MlKemCiphertext,
    pub signature: MlDsaSignature,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Confirm {
    pub meta: ControlMeta,
    pub signature: MlDsaSignature,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Ready {
    pub encrypted: EncryptedMessage,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ReadyBody {
    pub meta: ControlMeta,
}

pub fn verify_signature(
    signing_key: &MlDsaPublicKey,
    signature: &MlDsaSignature,
    proof_data: &[u8],
) -> Result<(), WireError> {
    if signing_key.verify(signature, proof_data) {
        Ok(())
    } else {
        Err(WireError::InvalidSignature)
    }
}
