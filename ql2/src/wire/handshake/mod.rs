use bc_components::{MLDSAPublicKey, MLDSASignature, MLKEMCiphertext, Nonce};
use rkyv::{Archive, Serialize};

use super::{
    mldsa_signature_from_archived, mlkem_ciphertext_from_archived, nonce_from_archived,
    AsWireMlDsaSignature, AsWireMlKemCiphertext, AsWireNonce,
};
use crate::QlError;

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Debug, Clone, PartialEq)]
pub enum HandshakeRecord {
    Hello(Hello),
    HelloReply(HelloReply),
    Confirm(Confirm),
}

impl TryFrom<&ArchivedHandshakeRecord> for HandshakeRecord {
    type Error = QlError;

    fn try_from(value: &ArchivedHandshakeRecord) -> Result<Self, Self::Error> {
        match value {
            ArchivedHandshakeRecord::Hello(message) => Ok(Self::Hello(message.try_into()?)),
            ArchivedHandshakeRecord::HelloReply(message) => {
                Ok(Self::HelloReply(message.try_into()?))
            }
            ArchivedHandshakeRecord::Confirm(message) => Ok(Self::Confirm(message.try_into()?)),
        }
    }
}

#[derive(Archive, Serialize, Debug, Clone, PartialEq)]
pub struct Hello {
    #[rkyv(with = AsWireNonce)]
    pub nonce: Nonce,
    #[rkyv(with = AsWireMlKemCiphertext)]
    pub kem_ct: MLKEMCiphertext,
}

impl TryFrom<&ArchivedHello> for Hello {
    type Error = QlError;

    fn try_from(value: &ArchivedHello) -> Result<Self, Self::Error> {
        Ok(Self {
            nonce: nonce_from_archived(&value.nonce),
            kem_ct: mlkem_ciphertext_from_archived(&value.kem_ct)?,
        })
    }
}

impl TryFrom<&Hello> for Hello {
    type Error = QlError;

    fn try_from(value: &Hello) -> Result<Self, Self::Error> {
        Ok(value.clone())
    }
}

#[derive(Archive, Serialize, Debug, Clone, PartialEq)]
pub struct HelloReply {
    #[rkyv(with = AsWireNonce)]
    pub nonce: Nonce,
    #[rkyv(with = AsWireMlKemCiphertext)]
    pub kem_ct: MLKEMCiphertext,
    #[rkyv(with = AsWireMlDsaSignature)]
    pub signature: MLDSASignature,
}

impl TryFrom<&ArchivedHelloReply> for HelloReply {
    type Error = QlError;

    fn try_from(value: &ArchivedHelloReply) -> Result<Self, Self::Error> {
        Ok(Self {
            nonce: nonce_from_archived(&value.nonce),
            kem_ct: mlkem_ciphertext_from_archived(&value.kem_ct)?,
            signature: mldsa_signature_from_archived(&value.signature)?,
        })
    }
}

impl TryFrom<&HelloReply> for HelloReply {
    type Error = QlError;

    fn try_from(value: &HelloReply) -> Result<Self, Self::Error> {
        Ok(value.clone())
    }
}

#[derive(Archive, Serialize, Debug, Clone, PartialEq)]
pub struct Confirm {
    #[rkyv(with = AsWireMlDsaSignature)]
    pub signature: MLDSASignature,
}

impl TryFrom<&ArchivedConfirm> for Confirm {
    type Error = QlError;

    fn try_from(value: &ArchivedConfirm) -> Result<Self, Self::Error> {
        Ok(Self {
            signature: mldsa_signature_from_archived(&value.signature)?,
        })
    }
}

impl TryFrom<&Confirm> for Confirm {
    type Error = QlError;

    fn try_from(value: &Confirm) -> Result<Self, Self::Error> {
        Ok(value.clone())
    }
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
