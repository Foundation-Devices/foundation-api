use bc_components::{Nonce, SymmetricKey};
use dcbor::CBOR;

use super::CallBody;
use crate::{
    wire::{ensure_not_expired, QlHeader, QlPayload, QlRecord},
    QlError,
};

pub fn encrypt_call(header: QlHeader, session_key: &SymmetricKey, body: CallBody) -> QlRecord {
    let aad = header.aad();
    let body_bytes = CBOR::from(body).to_cbor_data();
    let encrypted = session_key.encrypt(body_bytes, Some(aad), None::<Nonce>);
    QlRecord {
        header,
        payload: QlPayload::Call(encrypted),
    }
}

pub fn decrypt_call(
    header: &QlHeader,
    encrypted: &bc_components::EncryptedMessage,
    session_key: &SymmetricKey,
) -> Result<CallBody, QlError> {
    let aad = header.aad();
    if encrypted.aad() != aad {
        return Err(QlError::InvalidPayload);
    }
    let plaintext = session_key
        .decrypt(encrypted)
        .map_err(|_| QlError::InvalidPayload)?;
    let cbor = CBOR::try_from_data(plaintext).map_err(|_| QlError::InvalidPayload)?;
    let body = CallBody::try_from(cbor).map_err(|_| QlError::InvalidPayload)?;
    ensure_not_expired(body.valid_until)?;
    Ok(body)
}
