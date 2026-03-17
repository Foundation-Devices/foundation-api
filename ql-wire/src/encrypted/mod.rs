use rkyv::{Archive, Deserialize, Serialize};

use crate::{
    access_value, deserialize_value, encode_value,
    encrypted_message::{ArchivedEncryptedMessage, EncryptedMessage},
    Nonce, QlCrypto, QlHeader, QlPayload, QlRecord, SessionKey, SessionSeq, WireError,
};

pub mod close;
pub mod ping;
pub mod stream;
pub mod unpair;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SessionEnvelope {
    pub seq: SessionSeq,
    pub ack: SessionAck,
    pub body: SessionBody,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionAck {
    pub base: SessionSeq,
    pub bitmap: u64,
}

impl SessionAck {
    pub const EMPTY: Self = Self {
        base: SessionSeq(0),
        bitmap: 0,
    };
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SessionBody {
    Ack,
    Ping(ping::PingBody),
    Unpair(unpair::UnpairBody),
    Stream(stream::StreamFrame),
    StreamClose(stream::StreamCloseFrame),
    Close(close::SessionCloseBody),
}

pub fn encrypt_record(
    crypto: &impl QlCrypto,
    header: QlHeader,
    session_key: &SessionKey,
    body: &SessionEnvelope,
    nonce: Nonce,
) -> Result<QlRecord, WireError> {
    let aad = header.aad();
    let body_bytes = encode_value(body);
    let encrypted = EncryptedMessage::encrypt(crypto, session_key, body_bytes, &aad, nonce)?;
    Ok(QlRecord {
        header,
        payload: QlPayload::Encrypted(encrypted),
    })
}

pub fn decrypt_record(
    crypto: &impl QlCrypto,
    header: &QlHeader,
    encrypted: &mut ArchivedEncryptedMessage,
    session_key: &SessionKey,
) -> Result<SessionEnvelope, WireError> {
    let aad = header.aad();
    let plaintext = encrypted.decrypt(crypto, session_key, &aad)?;
    let body = access_value::<ArchivedSessionEnvelope>(plaintext)?;
    deserialize_value(body)
}
