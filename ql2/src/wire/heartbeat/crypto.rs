use bc_components::SymmetricKey;

use super::HeartbeatBody;
use crate::{
    wire::{
        access_value, deserialize_value, encode_value,
        encrypted_message::{ArchivedEncryptedMessage, EncryptedMessage, NONCE_SIZE},
        ensure_not_expired, QlHeader, QlPayload, QlRecord,
    },
    QlError,
};

pub fn encrypt_heartbeat(
    header: QlHeader,
    session_key: &SymmetricKey,
    body: HeartbeatBody,
    nonce: [u8; NONCE_SIZE],
) -> QlRecord {
    let aad = header.aad();
    let body_bytes = encode_value(&body);
    let encrypted = EncryptedMessage::encrypt(session_key, body_bytes, &aad, nonce);
    QlRecord {
        header,
        payload: QlPayload::Heartbeat(encrypted),
    }
}

pub(crate) fn decrypt_heartbeat(
    header: &QlHeader,
    encrypted: &mut ArchivedEncryptedMessage,
    session_key: &SymmetricKey,
) -> Result<HeartbeatBody, QlError> {
    let aad = header.aad();
    let plaintext = encrypted.decrypt(session_key, &aad)?;
    let body = access_value::<super::ArchivedHeartbeatBody>(plaintext)?;
    let body = deserialize_value(body)?;
    ensure_not_expired(body.valid_until)?;
    Ok(body)
}
