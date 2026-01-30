use std::time::{SystemTime, UNIX_EPOCH};

use bc_components::{Nonce, SymmetricKey};
use dcbor::CBOR;

use crate::{
    wire::{
        record::{DecryptedRecord, Nack, RecordBody, RecordKind},
        QlHeader, QlMessage, QlPayload,
    },
    MessageId, QlError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    Nack {
        id: MessageId,
        nack: Nack,
        kind: RecordKind,
    },
    Error(QlError),
}

pub fn encrypt_record(header: QlHeader, session_key: &SymmetricKey, body: RecordBody) -> QlMessage {
    let aad = CBOR::from(header.clone()).to_cbor_data();
    let body_bytes = CBOR::from(body).to_cbor_data();
    let encrypted = session_key.encrypt(body_bytes, Some(aad), None::<Nonce>);
    QlMessage {
        header,
        payload: QlPayload::Record(encrypted),
    }
}

pub fn decrypt_record(
    header: &QlHeader,
    encrypted: &bc_components::EncryptedMessage,
    session_key: &SymmetricKey,
) -> Result<DecryptedRecord, RecordError> {
    let aad = CBOR::from(header.clone()).to_cbor_data();
    if encrypted.aad() != aad {
        return Err(RecordError::Error(QlError::InvalidPayload));
    }
    let body = decrypt_body(session_key, encrypted)?;
    if now_secs() > body.valid_until {
        return Err(RecordError::Nack {
            id: body.message_id,
            nack: Nack::Expired,
            kind: body.kind,
        });
    }
    Ok(DecryptedRecord {
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
) -> Result<RecordBody, RecordError> {
    let plaintext = session_key
        .decrypt(encrypted)
        .map_err(|_| RecordError::Error(QlError::InvalidPayload))?;
    let cbor =
        CBOR::try_from_data(plaintext).map_err(|_| RecordError::Error(QlError::InvalidPayload))?;
    RecordBody::try_from(cbor).map_err(|_| RecordError::Error(QlError::InvalidPayload))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
