use bc_components::{Nonce, SymmetricKey};
use dcbor::CBOR;

use super::StreamBody;
use crate::{
    wire::{ensure_not_expired, QlHeader, QlPayload, QlRecord},
    QlError,
};

pub fn encrypt_stream(header: QlHeader, session_key: &SymmetricKey, body: StreamBody) -> QlRecord {
    let aad = header.aad();
    let body_bytes = CBOR::from(body).to_cbor_data();
    let encrypted = session_key.encrypt(body_bytes, Some(aad), None::<Nonce>);
    QlRecord {
        header,
        payload: QlPayload::Stream(encrypted),
    }
}

pub fn decrypt_stream(
    header: &QlHeader,
    encrypted: &bc_components::EncryptedMessage,
    session_key: &SymmetricKey,
) -> Result<StreamBody, QlError> {
    let aad = header.aad();
    if encrypted.aad() != aad {
        return Err(QlError::InvalidPayload);
    }
    let plaintext = session_key
        .decrypt(encrypted)
        .map_err(|_| QlError::InvalidPayload)?;
    let cbor = CBOR::try_from_data(plaintext).map_err(|_| QlError::InvalidPayload)?;
    let body = StreamBody::try_from(cbor).map_err(|_| QlError::InvalidPayload)?;
    ensure_not_expired(body.valid_until)?;
    Ok(body)
}
