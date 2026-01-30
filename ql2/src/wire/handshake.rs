use bc_components::{EncapsulationCiphertext, Nonce, Signature, SigningPublicKey, Verifier};
use dcbor::CBOR;

use super::take_fields;
use crate::QlError;

#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeMessage {
    Hello(Hello),
    HelloReply(HelloReply),
    Confirm(Confirm),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hello {
    pub nonce: Nonce,
    pub kem_ct: EncapsulationCiphertext,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HelloReply {
    pub nonce: Nonce,
    pub kem_ct: EncapsulationCiphertext,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Confirm {
    pub signature: Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeKind {
    Hello = 1,
    HelloReply,
    Confirm,
}

impl TryFrom<CBOR> for HandshakeKind {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let tag: u8 = value.try_into()?;
        match tag {
            1 => Ok(Self::Hello),
            2 => Ok(Self::HelloReply),
            3 => Ok(Self::Confirm),
            _ => Err(dcbor::Error::msg("unknown message tag")),
        }
    }
}

pub fn verify_transcript_signature(
    signing_key: &SigningPublicKey,
    signature: &Signature,
    transcript: &[u8],
) -> Result<(), QlError> {
    if signing_key.verify(signature, &transcript) {
        Ok(())
    } else {
        Err(QlError::InvalidSignature)
    }
}

impl From<HandshakeMessage> for CBOR {
    fn from(value: HandshakeMessage) -> Self {
        match value {
            HandshakeMessage::Hello(message) => CBOR::from(vec![
                CBOR::from(HandshakeKind::Hello as u8),
                CBOR::from(message.nonce),
                CBOR::from(message.kem_ct),
            ]),
            HandshakeMessage::HelloReply(message) => CBOR::from(vec![
                CBOR::from(HandshakeKind::HelloReply as u8),
                CBOR::from(message.nonce),
                CBOR::from(message.kem_ct),
                CBOR::from(message.signature),
            ]),
            HandshakeMessage::Confirm(message) => CBOR::from(vec![
                CBOR::from(HandshakeKind::Confirm as u8),
                CBOR::from(message.signature),
            ]),
        }
    }
}

impl TryFrom<CBOR> for HandshakeMessage {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let mut iter = value.try_into_array()?.into_iter();
        let tag: HandshakeKind = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("missing handshake tag"))?
            .try_into()?;
        match tag {
            HandshakeKind::Hello => {
                let [nonce_cbor, kem_ct_cbor] = take_fields(iter)?;
                Ok(HandshakeMessage::Hello(Hello {
                    nonce: nonce_cbor.try_into()?,
                    kem_ct: kem_ct_cbor.try_into()?,
                }))
            }
            HandshakeKind::HelloReply => {
                let [nonce_cbor, kem_ct_cbor, signature_cbor] = take_fields(iter)?;
                Ok(HandshakeMessage::HelloReply(HelloReply {
                    nonce: nonce_cbor.try_into()?,
                    kem_ct: kem_ct_cbor.try_into()?,
                    signature: signature_cbor.try_into()?,
                }))
            }
            HandshakeKind::Confirm => {
                let [signature_cbor] = take_fields(iter)?;
                Ok(HandshakeMessage::Confirm(Confirm {
                    signature: signature_cbor.try_into()?,
                }))
            }
        }
    }
}
