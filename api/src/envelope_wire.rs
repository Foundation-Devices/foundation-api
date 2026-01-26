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

#[derive(Debug, Clone, Copy)]
pub struct QlHeader {
    pub kind: MessageKind,
    pub id: ARID,
    pub sender: XID,
    pub recipient: XID,
}

impl From<QlHeader> for dcbor::CBOR {
    fn from(value: QlHeader) -> Self {
        dcbor::CBOR::from(vec![
            dcbor::CBOR::from(value.kind),
            dcbor::CBOR::from(value.id),
            dcbor::CBOR::from(value.sender),
            dcbor::CBOR::from(value.recipient),
        ])
    }
}

impl TryFrom<CBOR> for QlHeader {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        if array.len() != 4 {
            return Err(dcbor::Error::msg("invalid header length"));
        }
        let kind = MessageKind::try_from(array[0].clone())?;
        let id: ARID = array[1].clone().try_into()?;
        let sender: XID = array[2].clone().try_into()?;
        let recipient: XID = array[3].clone().try_into()?;
        Ok(Self {
            kind,
            id,
            sender,
            recipient,
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
    #[error("unknown signer")]
    UnknownSigner,
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

pub fn encode_ql_message(header: QlHeader, payload: Envelope, signer: &dyn Signer) -> Vec<u8> {
    let header_cbor = CBOR::from(header);
    let header_envelope = Envelope::new(header_cbor);
    let envelope = Envelope::new(known::FRAME)
        .add_assertion(known::HEADER, header_envelope)
        .add_assertion(known::PAYLOAD, payload)
        .sign(signer);
    envelope.to_cbor_data()
}

pub fn decode_ql_message(
    bytes: &[u8],
    resolver: impl Fn(&XID) -> Option<SigningPublicKey>,
) -> Result<QlMessage, DecodeError> {
    let cbor = dcbor::CBOR::try_from_data(bytes)?;
    let outer = Envelope::try_from_cbor(cbor)?;
    let unverified = outer.try_unwrap().unwrap_or_else(|_| outer.clone());
    let sender_header = extract_header(&unverified)?;
    let verifier = resolver(&sender_header.sender).ok_or(DecodeError::UnknownSigner)?;
    let decrypted = outer.verify(&verifier)?;

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
    fn decode_header_without_payload_decryption() {
        let sender = QuantumLinkIdentity::generate();
        let recipient = QuantumLinkIdentity::generate();
        let sender_xid: XID = sender.xid_document.clone().into();
        let recipient_xid: XID = recipient.xid_document.clone().into();
        let header = QlHeader {
            kind: MessageKind::Request,
            id: ARID::new(),
            sender: sender_xid,
            recipient: recipient_xid,
        };

        let payload = Envelope::new("secret");
        let encryption_key = recipient
            .xid_document
            .encryption_key()
            .expect("missing encryption key");
        let encrypted_payload = payload.encrypt_to_recipient(encryption_key);

        let signer = sender.private_keys.as_ref().expect("missing signer");
        let verifier = sender
            .xid_document
            .verification_key()
            .expect("missing signing public key")
            .clone();
        let bytes = encode_ql_message(header, encrypted_payload.clone(), signer);
        let decoded = decode_ql_message(&bytes, |xid| {
            if *xid == sender_xid {
                Some(verifier.clone())
            } else {
                None
            }
        })
        .expect("decode failed");

        assert_eq!(decoded.header.kind, header.kind);
        assert_eq!(decoded.header.id, header.id);
        assert_eq!(decoded.header.recipient, header.recipient);
        match decoded.payload.subject().case() {
            EnvelopeCase::Encrypted(_) => {}
            _ => panic!("payload should remain encrypted"),
        }
    }
}
