use std::time::{SystemTime, UNIX_EPOCH};

use bc_components::{EncapsulationCiphertext, EncryptedMessage, Signature, Signer, ARID, XID};
use dcbor::CBOR;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Response,
    Event,
    SessionReset,
}

#[derive(Debug, Clone)]
pub struct QlHeader {
    pub kind: MessageKind,
    pub id: ARID,
    pub sender: XID,
    pub recipient: XID,
    pub valid_until: u64,
    pub kem_ct: Option<EncapsulationCiphertext>,
    pub signature: Option<Signature>,
}

#[derive(Debug, Clone)]
pub struct QlHeaderUnsigned {
    pub kind: MessageKind,
    pub id: ARID,
    pub sender: XID,
    pub recipient: XID,
    pub valid_until: u64,
    pub kem_ct: Option<EncapsulationCiphertext>,
}

#[derive(Debug, Clone)]
pub struct EncodeQlConfig {
    pub sender: XID,
    pub recipient: XID,
    pub valid_until: u64,
    pub kem_ct: Option<EncapsulationCiphertext>,
    pub sign_header: bool,
}

impl QlHeader {
    pub fn unsigned(&self) -> QlHeaderUnsigned {
        QlHeaderUnsigned {
            kind: self.kind,
            id: self.id,
            sender: self.sender,
            recipient: self.recipient,
            valid_until: self.valid_until,
            kem_ct: self.kem_ct.clone(),
        }
    }

    pub fn aad_data(&self) -> Vec<u8> {
        CBOR::from(self.unsigned()).to_cbor_data()
    }
}

impl QlHeaderUnsigned {
    pub fn aad_data(&self) -> Vec<u8> {
        CBOR::from(self.clone()).to_cbor_data()
    }
}

impl From<QlHeader> for dcbor::CBOR {
    fn from(value: QlHeader) -> Self {
        dcbor::CBOR::from(vec![
            dcbor::CBOR::from(value.kind),
            dcbor::CBOR::from(value.id),
            dcbor::CBOR::from(value.sender),
            dcbor::CBOR::from(value.recipient),
            dcbor::CBOR::from(value.valid_until),
            option_to_cbor(value.kem_ct),
            option_to_cbor(value.signature),
        ])
    }
}

impl From<QlHeaderUnsigned> for dcbor::CBOR {
    fn from(value: QlHeaderUnsigned) -> Self {
        dcbor::CBOR::from(vec![
            dcbor::CBOR::from(value.kind),
            dcbor::CBOR::from(value.id),
            dcbor::CBOR::from(value.sender),
            dcbor::CBOR::from(value.recipient),
            dcbor::CBOR::from(value.valid_until),
            option_to_cbor(value.kem_ct),
        ])
    }
}

impl TryFrom<CBOR> for QlHeader {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        if array.len() != 7 {
            return Err(dcbor::Error::msg("invalid header length"));
        }
        let kind = MessageKind::try_from(array[0].clone())?;
        let id: ARID = array[1].clone().try_into()?;
        let sender: XID = array[2].clone().try_into()?;
        let recipient: XID = array[3].clone().try_into()?;
        let valid_until: u64 = array[4].clone().try_into()?;
        let kem_ct: Option<EncapsulationCiphertext> = option_from_cbor(array[5].clone())?;
        let signature: Option<Signature> = option_from_cbor(array[6].clone())?;
        Ok(Self {
            kind,
            id,
            sender,
            recipient,
            valid_until,
            kem_ct,
            signature,
        })
    }
}

fn option_to_cbor<T>(value: Option<T>) -> CBOR
where
    T: Into<CBOR>,
{
    value.map(Into::into).unwrap_or_else(CBOR::null)
}

fn option_from_cbor<T>(value: CBOR) -> dcbor::Result<Option<T>>
where
    T: TryFrom<CBOR, Error = dcbor::Error>,
{
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(value.try_into()?))
    }
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("invalid message encoding")]
    InvalidEncoding,
    #[error("message expired")]
    Expired,
    #[error(transparent)]
    Cbor(#[from] dcbor::Error),
}

#[derive(Debug)]
pub struct DecodeErrContext {
    pub error: DecodeError,
    pub header: Option<QlHeader>,
}

#[derive(Debug, Clone)]
pub struct QlMessage {
    pub header: QlHeader,
    pub payload: EncryptedMessage,
}

pub fn encode_ql_message(
    kind: MessageKind,
    id: ARID,
    config: EncodeQlConfig,
    payload: EncryptedMessage,
    signer: &dyn Signer,
) -> Vec<u8> {
    let header_unsigned = QlHeaderUnsigned {
        kind,
        id,
        sender: config.sender,
        recipient: config.recipient,
        valid_until: config.valid_until,
        kem_ct: config.kem_ct.clone(),
    };
    let signature = if config.sign_header {
        Some(
            signer
                .sign(&header_unsigned.aad_data())
                .expect("failed to sign header"),
        )
    } else {
        None
    };
    let header = QlHeader {
        kind,
        id,
        sender: config.sender,
        recipient: config.recipient,
        valid_until: config.valid_until,
        kem_ct: config.kem_ct,
        signature,
    };
    let cbor = CBOR::from(vec![CBOR::from(header), CBOR::from(payload)]);
    cbor.to_cbor_data()
}

pub fn decode_ql_message(bytes: &[u8]) -> Result<QlMessage, DecodeErrContext> {
    let cbor = dcbor::CBOR::try_from_data(bytes).map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: None,
    })?;
    let array = cbor.try_into_array().map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: None,
    })?;
    if array.len() != 2 {
        return Err(DecodeErrContext {
            error: DecodeError::InvalidEncoding,
            header: None,
        });
    }
    let header = QlHeader::try_from(array[0].clone()).map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: None,
    })?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    if now > header.valid_until {
        return Err(DecodeErrContext {
            error: DecodeError::Expired,
            header: Some(header),
        });
    }
    let payload: EncryptedMessage =
        array[1]
            .clone()
            .try_into()
            .map_err(|error| DecodeErrContext {
                error: DecodeError::Cbor(error),
                header: Some(header.clone()),
            })?;
    Ok(QlMessage { header, payload })
}

impl TryFrom<CBOR> for MessageKind {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let kind: u64 = value.try_into()?;
        match kind {
            1 => Ok(MessageKind::Request),
            2 => Ok(MessageKind::Response),
            3 => Ok(MessageKind::Event),
            4 => Ok(MessageKind::SessionReset),
            _ => Err(dcbor::Error::msg("unknown message kind")),
        }
    }
}

impl From<MessageKind> for CBOR {
    fn from(value: MessageKind) -> Self {
        let kind = match value {
            MessageKind::Request => 1,
            MessageKind::Response => 2,
            MessageKind::Event => 3,
            MessageKind::SessionReset => 4,
        };
        CBOR::from(kind)
    }
}

#[cfg(test)]
mod tests {
    use bc_components::Verifier;

    use super::*;
    use crate::test_identity::TestIdentity;

    #[test]
    fn round_trip() {
        let sender = TestIdentity::generate();
        let recipient = TestIdentity::generate();
        let recipient_xid = recipient.xid;
        let sender_xid = sender.xid;
        let header_id = ARID::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let valid_until = now.saturating_add(60);
        let (session_key, kem_ct) = recipient
            .encapsulation_public_key
            .encapsulate_new_shared_secret();
        let header_unsigned = QlHeaderUnsigned {
            kind: MessageKind::Request,
            id: header_id,
            sender: sender_xid,
            recipient: recipient_xid,
            valid_until,
            kem_ct: Some(kem_ct.clone()),
        };
        let payload = CBOR::from("secret");
        let payload_bytes = payload.to_cbor_data();
        let encrypted_payload = session_key.encrypt(
            payload_bytes,
            Some(header_unsigned.aad_data()),
            None::<bc_components::Nonce>,
        );

        let bytes = encode_ql_message(
            MessageKind::Request,
            header_id,
            EncodeQlConfig {
                sender: sender_xid,
                recipient: recipient_xid,
                valid_until,
                kem_ct: Some(kem_ct),
                sign_header: true,
            },
            encrypted_payload,
            &sender.private_keys,
        );
        let decoded = decode_ql_message(&bytes).expect("decode failed");

        assert_eq!(decoded.header.kind, MessageKind::Request);
        assert_eq!(decoded.header.id, header_id);
        assert_eq!(decoded.header.recipient, recipient_xid);
        assert_eq!(decoded.header.sender, sender_xid);

        let signing_data = decoded.header.unsigned().aad_data();
        let signature = decoded.header.signature.as_ref().expect("signature");
        assert!(sender.signing_public_key.verify(signature, &signing_data));

        let decrypted = session_key.decrypt(&decoded.payload).expect("decrypt");
        let decrypted_cbor = CBOR::try_from_data(decrypted).expect("cbor");
        assert_eq!(decrypted_cbor, payload);
    }

    #[test]
    fn header_size() {
        let size = std::mem::size_of::<QlHeader>();
        println!("header size: {} bytes", size);
        assert!(size > 0);
    }

    #[test]
    fn encoded_message_size() {
        let sender = TestIdentity::generate();
        let recipient = TestIdentity::generate();
        let recipient_xid = recipient.xid;
        let sender_xid = sender.xid;
        let header_id = ARID::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let valid_until = now.saturating_add(60);
        let (session_key, kem_ct) = recipient
            .encapsulation_public_key
            .encapsulate_new_shared_secret();
        let header_unsigned = QlHeaderUnsigned {
            kind: MessageKind::Request,
            id: header_id,
            sender: sender_xid,
            recipient: recipient_xid,
            valid_until,
            kem_ct: Some(kem_ct.clone()),
        };
        let payload = CBOR::from("size");
        let payload_bytes = payload.to_cbor_data();
        let encrypted_payload = session_key.encrypt(
            payload_bytes,
            Some(header_unsigned.aad_data()),
            None::<bc_components::Nonce>,
        );

        let bytes = encode_ql_message(
            MessageKind::Request,
            header_id,
            EncodeQlConfig {
                sender: sender_xid,
                recipient: recipient_xid,
                valid_until,
                kem_ct: Some(kem_ct),
                sign_header: true,
            },
            encrypted_payload,
            &sender.private_keys,
        );

        println!("encoded message size: {} bytes", bytes.len());
        assert!(!bytes.is_empty());
    }

    #[test]
    fn steady_state_message_size() {
        let sender = TestIdentity::generate();
        let recipient = TestIdentity::generate();
        let recipient_xid = recipient.xid;
        let sender_xid = sender.xid;
        let header_id = ARID::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let valid_until = now.saturating_add(60);
        let (session_key, _kem_ct) = recipient
            .encapsulation_public_key
            .encapsulate_new_shared_secret();
        let header_unsigned = QlHeaderUnsigned {
            kind: MessageKind::Request,
            id: header_id,
            sender: sender_xid,
            recipient: recipient_xid,
            valid_until,
            kem_ct: None,
        };
        let payload = CBOR::from("steady");
        let payload_bytes = payload.to_cbor_data();
        let encrypted_payload = session_key.encrypt(
            payload_bytes,
            Some(header_unsigned.aad_data()),
            None::<bc_components::Nonce>,
        );

        let bytes = encode_ql_message(
            MessageKind::Request,
            header_id,
            EncodeQlConfig {
                sender: sender_xid,
                recipient: recipient_xid,
                valid_until,
                kem_ct: None,
                sign_header: false,
            },
            encrypted_payload,
            &sender.private_keys,
        );

        println!("steady-state message size: {} bytes", bytes.len());
        assert!(!bytes.is_empty());
    }
}
