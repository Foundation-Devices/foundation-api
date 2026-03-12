use bc_components::SymmetricKey;

use super::StreamMessage;
use crate::{
    wire::{
        access_value, deserialize_value, encode_value,
        encrypted_message::{ArchivedEncryptedMessage, EncryptedMessage, NONCE_SIZE},
        ensure_not_expired, QlHeader, QlPayload, QlRecord,
    },
    QlError,
};

pub fn encrypt_stream(
    header: QlHeader,
    session_key: &SymmetricKey,
    message: StreamMessage,
    nonce: [u8; NONCE_SIZE],
) -> QlRecord {
    let aad = header.aad();
    let body_bytes = encode_value(&message);
    let encrypted = EncryptedMessage::encrypt(session_key, body_bytes, &aad, nonce);
    QlRecord {
        header,
        payload: QlPayload::Stream(encrypted),
    }
}

pub(crate) fn decrypt_stream(
    header: &QlHeader,
    encrypted: &mut ArchivedEncryptedMessage,
    session_key: &SymmetricKey,
) -> Result<StreamMessage, QlError> {
    let aad = header.aad();
    let plaintext = encrypted.decrypt(session_key, &aad)?;
    let message = access_value::<super::ArchivedStreamMessage>(plaintext)?;
    let message = deserialize_value(message)?;
    ensure_not_expired(message.valid_until)?;
    Ok(message)
}
