use bc_components::SymmetricKey;

use super::StreamBody;
use crate::{
    wire::{
        access_value, deserialize_value, encode_value, encrypted_message_from_archived,
        ensure_not_expired, ArchivedQlHeader, ArchivedWireEncryptedMessage, QlHeader, QlPayload,
        QlRecord,
    },
    QlError,
};

pub fn encrypt_stream(header: QlHeader, session_key: &SymmetricKey, body: StreamBody) -> QlRecord {
    let aad = header.aad();
    let body_bytes = encode_value(&body);
    let encrypted = session_key.encrypt(body_bytes, Some(aad), None::<bc_components::Nonce>);
    QlRecord {
        header,
        payload: QlPayload::Stream(encrypted),
    }
}

pub(crate) fn decrypt_stream(
    header: &ArchivedQlHeader,
    encrypted: &ArchivedWireEncryptedMessage,
    session_key: &SymmetricKey,
) -> Result<StreamBody, QlError> {
    let header = deserialize_value(header)?;
    let encrypted = encrypted_message_from_archived(encrypted);
    let aad = header.aad();
    if encrypted.aad() != aad {
        return Err(QlError::InvalidPayload);
    }
    let plaintext = session_key
        .decrypt(&encrypted)
        .map_err(|_| QlError::InvalidPayload)?;
    let body = access_value::<super::ArchivedStreamBody>(&plaintext)?;
    let body = deserialize_value(body)?;
    ensure_not_expired(body.valid_until)?;
    Ok(body)
}
