use bc_components::{Nonce, SymmetricKey};
use dcbor::CBOR;

use super::TransferBody;
use crate::{
    wire::{now_secs, QlHeader, QlPayload, QlRecord},
    QlError,
};

pub fn encrypt_transfer(
    header: QlHeader,
    session_key: &SymmetricKey,
    body: TransferBody,
) -> QlRecord {
    let aad = header.aad();
    let body_bytes = CBOR::from(body).to_cbor_data();
    let encrypted = session_key.encrypt(body_bytes, Some(aad), None::<Nonce>);
    QlRecord {
        header,
        payload: QlPayload::Transfer(encrypted),
    }
}

pub fn decrypt_transfer(
    header: &QlHeader,
    encrypted: &bc_components::EncryptedMessage,
    session_key: &SymmetricKey,
) -> Result<TransferBody, QlError> {
    let aad = header.aad();
    if encrypted.aad() != aad {
        return Err(QlError::InvalidPayload);
    }
    let plaintext = session_key
        .decrypt(encrypted)
        .map_err(|_| QlError::InvalidPayload)?;
    let cbor = CBOR::try_from_data(plaintext).map_err(|_| QlError::InvalidPayload)?;
    let body = TransferBody::try_from(cbor).map_err(|_| QlError::InvalidPayload)?;
    if now_secs() > body.valid_until {
        return Err(QlError::InvalidPayload);
    }
    Ok(body)
}
