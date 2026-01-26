use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bc_components::{Signer, SigningPublicKey, ARID, XID};
use bc_envelope::{Envelope, EnvelopeCase, KnownValue};
use dcbor::{CBOREncodable, CBOR};
use thiserror::Error;

pub mod known {
    use super::*;

    pub const FRAME: KnownValue = KnownValue::new_with_static_name(7000, "frame");
    pub const HEADER: KnownValue = KnownValue::new_with_static_name(7001, "header");
    pub const PAYLOAD: KnownValue = KnownValue::new_with_static_name(7002, "payload");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Response,
    Event,
}

#[derive(Debug, Clone)]
pub struct QlHeader {
    pub kind: MessageKind,
    pub id: ARID,
    pub signing_key: SigningPublicKey,
    pub recipient: XID,
    pub valid_until: u64,
}

#[derive(Debug, Clone)]
pub struct EncodeQlConfig {
    pub signing_key: SigningPublicKey,
    pub recipient: XID,
    pub valid_for: Duration,
}

impl QlHeader {
    pub fn sender_xid(&self) -> XID {
        XID::new(&self.signing_key)
    }
}

impl From<QlHeader> for dcbor::CBOR {
    fn from(value: QlHeader) -> Self {
        dcbor::CBOR::from(vec![
            dcbor::CBOR::from(value.kind),
            dcbor::CBOR::from(value.id),
            dcbor::CBOR::from(value.signing_key.clone()),
            dcbor::CBOR::from(value.recipient),
            dcbor::CBOR::from(value.valid_until),
        ])
    }
}

impl TryFrom<CBOR> for QlHeader {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        if array.len() != 5 {
            return Err(dcbor::Error::msg("invalid header length"));
        }
        let kind = MessageKind::try_from(array[0].clone())?;
        let id: ARID = array[1].clone().try_into()?;
        let signing_key: SigningPublicKey = array[2].clone().try_into()?;
        let recipient: XID = array[3].clone().try_into()?;
        let valid_until: u64 = array[4].clone().try_into()?;
        Ok(Self {
            kind,
            id,
            signing_key,
            recipient,
            valid_until,
        })
    }
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("invalid envelope encoding")]
    InvalidEncoding,
    #[error("missing or invalid field: {0}")]
    InvalidField(KnownValue),
    #[error("unknown message kind")]
    UnknownKind,
    #[error("message expired")]
    Expired,
    #[error(transparent)]
    Envelope(#[from] bc_envelope::Error),
    #[error(transparent)]
    Cbor(#[from] dcbor::Error),
}

#[derive(Debug, Clone)]
pub struct QlMessage {
    pub header: QlHeader,
    /// Encrypted payload envelope (opaque to the executor).
    pub payload: Envelope,
}

pub fn encode_ql_message(
    kind: MessageKind,
    id: ARID,
    config: EncodeQlConfig,
    payload: Envelope,
    signer: &dyn Signer,
) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let header = QlHeader {
        kind,
        id,
        signing_key: config.signing_key,
        recipient: config.recipient,
        valid_until: now.saturating_add(config.valid_for.as_secs()),
    };
    let header_cbor = CBOR::from(header);
    let header_envelope = Envelope::new(header_cbor);
    let envelope = Envelope::new(known::FRAME)
        .add_assertion(known::HEADER, header_envelope)
        .add_assertion(known::PAYLOAD, payload)
        .sign(signer);
    envelope.to_cbor_data()
}

pub fn decode_ql_message(bytes: &[u8]) -> Result<QlMessage, DecodeError> {
    let cbor = dcbor::CBOR::try_from_data(bytes)?;
    let outer = Envelope::try_from_cbor(cbor)?;
    let unverified = outer.try_unwrap().unwrap_or_else(|_| outer.clone());
    let sender_header = extract_header(&unverified)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    if now > sender_header.valid_until {
        return Err(DecodeError::Expired);
    }
    let decrypted = outer.verify(&sender_header.signing_key)?;

    let header = extract_header(&decrypted)?;

    let payload: Envelope = decrypted
        .object_for_predicate(known::PAYLOAD)
        .map_err(|_| DecodeError::InvalidField(known::PAYLOAD))?;

    Ok(QlMessage { header, payload })
}

fn extract_header(envelope: &Envelope) -> Result<QlHeader, DecodeError> {
    let header_envelope = envelope
        .object_for_predicate(known::HEADER)
        .map_err(|_| DecodeError::InvalidField(known::HEADER))?;
    let header_subject = header_envelope.subject();
    let header_cbor = match header_subject.case() {
        EnvelopeCase::Leaf { cbor, .. } => cbor.clone(),
        _ => return Err(DecodeError::InvalidField(known::HEADER)),
    };
    QlHeader::try_from(header_cbor).map_err(DecodeError::Cbor)
}

impl TryFrom<CBOR> for MessageKind {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let kind: u64 = value.try_into()?;
        match kind {
            1 => Ok(MessageKind::Request),
            2 => Ok(MessageKind::Response),
            3 => Ok(MessageKind::Event),
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
        };
        CBOR::from(kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::quantum_link::QuantumLinkIdentity;

    #[test]
    fn round_trip() {
        let sender = QuantumLinkIdentity::generate();
        let recipient = QuantumLinkIdentity::generate();
        let recipient_xid: XID = recipient.xid_document.clone().into();
        let signing_key = sender
            .xid_document
            .verification_key()
            .expect("missing signing public key")
            .clone();
        let header_id = ARID::new();

        let payload = Envelope::new("secret");
        let encryption_key = recipient
            .xid_document
            .encryption_key()
            .expect("missing encryption key");
        let encrypted_payload = payload.encrypt_to_recipient(encryption_key);

        let signer = sender.private_keys.as_ref().expect("missing signer");
        let bytes = encode_ql_message(
            MessageKind::Request,
            header_id,
            EncodeQlConfig {
                signing_key: signing_key.clone(),
                recipient: recipient_xid,
                valid_for: Duration::from_secs(60),
            },
            encrypted_payload.clone(),
            signer,
        );
        let decoded = decode_ql_message(&bytes).expect("decode failed");

        assert_eq!(decoded.header.kind, MessageKind::Request);
        assert_eq!(decoded.header.id, header_id);
        assert_eq!(decoded.header.recipient, recipient_xid);
        match decoded.payload.subject().case() {
            EnvelopeCase::Encrypted(_) => {}
            _ => panic!("payload should remain encrypted"),
        }
    }

    #[test]
    fn header_size() {
        let size = std::mem::size_of::<QlHeader>();
        assert_eq!(size, 240);
    }
}
