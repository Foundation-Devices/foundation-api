use bc_components::{Nonce, SymmetricKey};
use dcbor::CBOR;

use crate::{
    crypto::ensure_not_expired,
    wire::{heartbeat::HeartbeatBody, QlHeader, QlPayload, QlRecord},
    QlError,
};

pub fn encrypt_heartbeat(
    header: QlHeader,
    session_key: &SymmetricKey,
    body: HeartbeatBody,
) -> QlRecord {
    let aad = header.aad();
    let body_bytes = CBOR::from(body).to_cbor_data();
    let encrypted = session_key.encrypt(body_bytes, Some(aad), None::<Nonce>);
    QlRecord {
        header,
        payload: QlPayload::Heartbeat(encrypted),
    }
}

pub fn decrypt_heartbeat(
    header: &QlHeader,
    encrypted: &bc_components::EncryptedMessage,
    session_key: &SymmetricKey,
) -> Result<HeartbeatBody, QlError> {
    let aad = header.aad();
    if encrypted.aad() != aad {
        return Err(QlError::InvalidPayload);
    }
    let plaintext = session_key
        .decrypt(encrypted)
        .map_err(|_| QlError::InvalidPayload)?;
    let cbor = CBOR::try_from_data(plaintext).map_err(|_| QlError::InvalidPayload)?;
    let body = HeartbeatBody::try_from(cbor).map_err(|_| QlError::InvalidPayload)?;
    ensure_not_expired(body.message_id, body.valid_until)?;
    Ok(body)
}
