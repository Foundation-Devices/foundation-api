use bc_components::{EncapsulationCiphertext, Nonce, Signature, SigningPublicKey, Verifier, XID};
use dcbor::CBOR;

use crate::QlError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeKind {
    Hello,
    HelloReply,
    Confirm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeHeader {
    pub kind: HandshakeKind,
    pub sender: XID,
    pub recipient: XID,
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

#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeMessage {
    Hello(Hello),
    HelloReply(HelloReply),
    Confirm(Confirm),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeTag {
    Hello = 0,
    HelloReply = 1,
    Confirm = 2,
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
                CBOR::from(HandshakeTag::Hello as u8),
                CBOR::from(message.header.sender),
                CBOR::from(message.header.recipient),
                CBOR::from(message.nonce),
                CBOR::from(message.kem_ct),
            ]),
            HandshakeMessage::HelloReply(message) => CBOR::from(vec![
                CBOR::from(HandshakeTag::HelloReply as u8),
                CBOR::from(message.header.sender),
                CBOR::from(message.header.recipient),
                CBOR::from(message.nonce),
                CBOR::from(message.kem_ct),
                CBOR::from(message.signature),
            ]),
            HandshakeMessage::Confirm(message) => CBOR::from(vec![
                CBOR::from(HandshakeTag::Confirm as u8),
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
        let tag: u8 = array
            .first()
            .cloned()
            .ok_or_else(|| dcbor::Error::msg("missing handshake tag"))?
            .try_into()?;
        match tag {
            x if x == HandshakeTag::Hello as u8 => {
                let [_tag, sender_cbor, recipient_cbor, nonce_cbor, kem_ct_cbor] =
                    cbor_array::<5>(array)?;
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
            x if x == HandshakeTag::HelloReply as u8 => {
                let [_tag, sender_cbor, recipient_cbor, nonce_cbor, kem_ct_cbor, signature_cbor] =
                    cbor_array::<6>(array)?;
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
            x if x == HandshakeTag::Confirm as u8 => {
                let [_tag, sender_cbor, recipient_cbor, signature_cbor] = cbor_array::<4>(array)?;
                Ok(HandshakeMessage::Confirm(Confirm {
                    header: HandshakeHeader {
                        kind: HandshakeKind::Confirm,
                        sender: sender_cbor.try_into()?,
                        recipient: recipient_cbor.try_into()?,
                    },
                    signature: signature_cbor.try_into()?,
                }))
            }
            _ => Err(dcbor::Error::msg("unknown handshake tag")),
        }
    }
}

fn cbor_array<const N: usize>(array: Vec<CBOR>) -> Result<[CBOR; N], dcbor::Error> {
    if array.len() != N {
        return Err(dcbor::Error::msg("invalid array length"));
    }
    array
        .try_into()
        .map_err(|_| dcbor::Error::msg("invalid array length"))
}
