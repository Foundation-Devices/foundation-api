use bc_components::{Nonce, SymmetricKey};
use dcbor::CBOR;

use crate::{
    crypto::ensure_not_expired,
    wire::{
        message::{DecryptedMessage, MessageBody, MessageKind, Nack},
        QlHeader, QlPayload, QlRecord,
    },
    MessageId, QlError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    Nack {
        id: MessageId,
        nack: Nack,
        kind: MessageKind,
    },
    Error(QlError),
}

impl From<QlError> for MessageError {
    fn from(value: QlError) -> Self {
        Self::Error(value)
    }
}

pub fn encrypt_message(
    header: QlHeader,
    session_key: &SymmetricKey,
    body: MessageBody,
) -> QlRecord {
    let aad = CBOR::from(header.clone()).to_cbor_data();
    let body_bytes = CBOR::from(body).to_cbor_data();
    let encrypted = session_key.encrypt(body_bytes, Some(aad), None::<Nonce>);
    QlRecord {
        header,
        payload: QlPayload::Message(encrypted),
    }
}

pub fn decrypt_message(
    header: &QlHeader,
    encrypted: &bc_components::EncryptedMessage,
    session_key: &SymmetricKey,
) -> Result<DecryptedMessage, MessageError> {
    let aad = header.aad();
    if encrypted.aad() != aad {
        return Err(QlError::InvalidPayload.into());
    }
    let body = decrypt_body(session_key, encrypted)?;
    ensure_not_expired(body.message_id, body.valid_until)?;
    Ok(DecryptedMessage {
        sender: header.sender,
        recipient: header.recipient,
        kind: body.kind,
        message_id: body.message_id,
        route_id: body.route_id,
        valid_until: body.valid_until,
        payload: body.payload,
    })
}

fn decrypt_body(
    session_key: &SymmetricKey,
    encrypted: &bc_components::EncryptedMessage,
) -> Result<MessageBody, QlError> {
    let plaintext = session_key
        .decrypt(encrypted)
        .map_err(|_| QlError::InvalidPayload)?;
    let cbor = CBOR::try_from_data(plaintext).map_err(|_| QlError::InvalidPayload)?;
    MessageBody::try_from(cbor).map_err(|_| QlError::InvalidPayload)
}
