use bc_components::{EncapsulationCiphertext, Nonce, Signature, SigningPublicKey, Verifier, XID};
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
    pub header: HandshakeHeader,
    pub nonce: Nonce,
    pub kem_ct: EncapsulationCiphertext,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HelloReply {
    pub header: HandshakeHeader,
    pub nonce: Nonce,
    pub kem_ct: EncapsulationCiphertext,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Confirm {
    pub header: HandshakeHeader,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeHeader {
    pub kind: HandshakeKind,
    pub sender: XID,
    pub recipient: XID,
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
                CBOR::from(message.header.sender),
                CBOR::from(message.header.recipient),
                CBOR::from(message.nonce),
                CBOR::from(message.kem_ct),
            ]),
            HandshakeMessage::HelloReply(message) => CBOR::from(vec![
                CBOR::from(HandshakeKind::HelloReply as u8),
                CBOR::from(message.header.sender),
                CBOR::from(message.header.recipient),
                CBOR::from(message.nonce),
                CBOR::from(message.kem_ct),
                CBOR::from(message.signature),
            ]),
            HandshakeMessage::Confirm(message) => CBOR::from(vec![
                CBOR::from(HandshakeKind::Confirm as u8),
                CBOR::from(message.header.sender),
                CBOR::from(message.header.recipient),
                CBOR::from(message.signature),
            ]),
        }
    }
}

impl TryFrom<CBOR> for HandshakeMessage {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        let mut iter = array.into_iter();
        let tag: HandshakeKind = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("missing handshake tag"))?
            .try_into()?;
        match tag {
            HandshakeKind::Hello => {
                let [sender_cbor, recipient_cbor, nonce_cbor, kem_ct_cbor] = take_fields(iter)?;
                Ok(HandshakeMessage::Hello(Hello {
                    header: HandshakeHeader {
                        kind: HandshakeKind::Hello,
                        sender: sender_cbor.try_into()?,
                        recipient: recipient_cbor.try_into()?,
                    },
                    nonce: nonce_cbor.try_into()?,
                    kem_ct: kem_ct_cbor.try_into()?,
                }))
            }
            HandshakeKind::HelloReply => {
                let [sender_cbor, recipient_cbor, nonce_cbor, kem_ct_cbor, signature_cbor] =
                    take_fields(iter)?;
                Ok(HandshakeMessage::HelloReply(HelloReply {
                    header: HandshakeHeader {
                        kind: HandshakeKind::HelloReply,
                        sender: sender_cbor.try_into()?,
                        recipient: recipient_cbor.try_into()?,
                    },
                    nonce: nonce_cbor.try_into()?,
                    kem_ct: kem_ct_cbor.try_into()?,
                    signature: signature_cbor.try_into()?,
                }))
            }
            HandshakeKind::Confirm => {
                let [sender_cbor, recipient_cbor, signature_cbor] = take_fields(iter)?;
                Ok(HandshakeMessage::Confirm(Confirm {
                    header: HandshakeHeader {
                        kind: HandshakeKind::Confirm,
                        sender: sender_cbor.try_into()?,
                        recipient: recipient_cbor.try_into()?,
                    },
                    signature: signature_cbor.try_into()?,
                }))
            }
        }
    }
}
