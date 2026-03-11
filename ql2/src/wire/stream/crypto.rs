use bc_components::SymmetricKey;

use super::StreamBody;
use crate::{
    wire::{
        access_value, deserialize_value, encode_value,
        encrypted_message::{ArchivedEncryptedMessage, EncryptedMessage},
        ensure_not_expired, QlHeader, QlPayload, QlRecord,
    },
    QlError,
};

pub fn encrypt_stream(header: QlHeader, session_key: &SymmetricKey, body: StreamBody) -> QlRecord {
    let aad = header.aad();
    let body_bytes = encode_value(&body);
    let encrypted = EncryptedMessage::encrypt(session_key, body_bytes, &aad);
    QlRecord {
        header,
        payload: QlPayload::Stream(encrypted),
    }
}

pub(crate) fn decrypt_stream(
    header: &QlHeader,
    encrypted: &mut ArchivedEncryptedMessage,
    session_key: &SymmetricKey,
) -> Result<StreamBody, QlError> {
    let aad = header.aad();
    let plaintext = encrypted.decrypt(session_key, &aad)?;
    let body = access_value::<super::ArchivedStreamBody>(&plaintext)?;
    let body = deserialize_value(body)?;
    ensure_not_expired(body.valid_until)?;
    Ok(body)
}
