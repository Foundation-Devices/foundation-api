use bc_components::{EncapsulationCiphertext, EncryptedMessage, Signature, ARID, XID};
use dcbor::CBOR;
use thiserror::Error;

use crate::cbor::{cbor_array, option_from_cbor, option_to_cbor};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Response,
    Event,
    SessionReset,
    Pairing,
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

impl QlHeader {
    pub fn aad_data(&self) -> Vec<u8> {
        header_cbor_unsigned(
            self.kind,
            self.id,
            self.sender,
            self.recipient,
            self.valid_until,
            self.kem_ct.clone(),
        )
        .to_cbor_data()
    }
}

impl From<QlHeader> for dcbor::CBOR {
    fn from(value: QlHeader) -> Self {
        header_cbor(
            value.kind,
            value.id,
            value.sender,
            value.recipient,
            value.valid_until,
            value.kem_ct,
            value.signature,
        )
    }
}

impl TryFrom<CBOR> for QlHeader {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        let [kind_cbor, id_cbor, sender_cbor, recipient_cbor, valid_until_cbor, kem_ct_cbor, signature_cbor] =
            cbor_array::<7>(array)?;
        let kind = kind_cbor.try_into()?;
        let id = id_cbor.try_into()?;
        let sender = sender_cbor.try_into()?;
        let recipient = recipient_cbor.try_into()?;
        let valid_until = valid_until_cbor.try_into()?;
        let kem_ct = option_from_cbor(kem_ct_cbor)?;
        let signature = option_from_cbor(signature_cbor)?;
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

fn header_cbor(
    kind: MessageKind,
    id: ARID,
    sender: XID,
    recipient: XID,
    valid_until: u64,
    kem_ct: Option<EncapsulationCiphertext>,
    signature: Option<Signature>,
) -> CBOR {
    CBOR::from(vec![
        CBOR::from(kind),
        CBOR::from(id),
        CBOR::from(sender),
        CBOR::from(recipient),
        CBOR::from(valid_until),
        option_to_cbor(kem_ct),
        option_to_cbor(signature),
    ])
}

fn header_cbor_unsigned(
    kind: MessageKind,
    id: ARID,
    sender: XID,
    recipient: XID,
    valid_until: u64,
    kem_ct: Option<EncapsulationCiphertext>,
) -> CBOR {
    CBOR::from(vec![
        CBOR::from(kind),
        CBOR::from(id),
        CBOR::from(sender),
        CBOR::from(recipient),
        CBOR::from(valid_until),
        option_to_cbor(kem_ct),
    ])
}

#[derive(Debug, Error)]
pub enum DecodeError {
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

pub fn encode_ql_message(header: QlHeader, payload: EncryptedMessage) -> Vec<u8> {
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
    let [header_cbor, payload_cbor] = cbor_array::<2>(array).map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: None,
    })?;
    let header = QlHeader::try_from(header_cbor).map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: None,
    })?;
    let payload: EncryptedMessage = payload_cbor.try_into().map_err(|error| DecodeErrContext {
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
            5 => Ok(MessageKind::Pairing),
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
            MessageKind::Pairing => 5,
        };
        CBOR::from(kind)
    }
}

#[cfg(test)]
mod tests {
    use bc_components::SymmetricKey;

    use super::*;
    use crate::test_identity::TestIdentity;

    #[test]
    fn round_trip() {
        let sender = TestIdentity::generate();
        let recipient = TestIdentity::generate();
        let recipient_xid = recipient.xid;
        let sender_xid = sender.xid;
        let header_id = ARID::new();
        let valid_until = 123;
        let header = QlHeader {
            kind: MessageKind::Request,
            id: header_id,
            sender: sender_xid,
            recipient: recipient_xid,
            valid_until,
            kem_ct: None,
            signature: None,
        };
        let payload = CBOR::from("secret");
        let payload_bytes = payload.to_cbor_data();
        let encrypted_payload = SymmetricKey::new().encrypt(
            payload_bytes,
            None::<Vec<u8>>,
            None::<bc_components::Nonce>,
        );

        let bytes = encode_ql_message(header.clone(), encrypted_payload);
        let decoded = decode_ql_message(&bytes).expect("decode failed");

        assert_eq!(decoded.header.kind, MessageKind::Request);
        assert_eq!(decoded.header.id, header_id);
        assert_eq!(decoded.header.recipient, recipient_xid);
        assert_eq!(decoded.header.sender, sender_xid);

        let reencoded = encode_ql_message(decoded.header, decoded.payload);
        assert_eq!(reencoded, bytes);
    }
}
