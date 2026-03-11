use bc_components::SymmetricKey;

use super::StreamBody;
use crate::{
    wire::{
        access_value, encode_value, encrypted_message_from_archived, ensure_not_expired,
        ArchivedWireEncryptedMessage, QlHeader, QlPayload, QlRecord,
    },
    QlError,
};

pub(crate) trait EncryptedInput {
    fn into_encrypted(self) -> Result<bc_components::EncryptedMessage, QlError>;
}

impl EncryptedInput for &bc_components::EncryptedMessage {
    fn into_encrypted(self) -> Result<bc_components::EncryptedMessage, QlError> {
        Ok(self.clone())
    }
}

impl EncryptedInput for &ArchivedWireEncryptedMessage {
    fn into_encrypted(self) -> Result<bc_components::EncryptedMessage, QlError> {
        Ok(encrypted_message_from_archived(self))
    }
}

pub fn encrypt_stream(header: QlHeader, session_key: &SymmetricKey, body: StreamBody) -> QlRecord {
    let aad = header.aad();
    let body_bytes = encode_value(&body);
    let encrypted = session_key.encrypt(body_bytes, Some(aad), None::<bc_components::Nonce>);
    QlRecord {
        header,
        payload: QlPayload::Stream(encrypted),
    }
}

pub(crate) fn decrypt_stream<H, E>(
    header: H,
    encrypted: E,
    session_key: &SymmetricKey,
) -> Result<StreamBody, QlError>
where
    H: TryInto<QlHeader, Error = QlError>,
    E: EncryptedInput,
{
    let header = header.try_into()?;
    let encrypted = encrypted.into_encrypted()?;
    let aad = header.aad();
    if encrypted.aad() != aad {
        return Err(QlError::InvalidPayload);
    }
    let plaintext = session_key
        .decrypt(&encrypted)
        .map_err(|_| QlError::InvalidPayload)?;
    let body = access_value::<super::ArchivedStreamBody>(&plaintext)?;
    let body = StreamBody::try_from(body)?;
    ensure_not_expired(body.valid_until)?;
    Ok(body)
}
