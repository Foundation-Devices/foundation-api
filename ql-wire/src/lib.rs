//! quantum link protocol wire format
//!
//! naming conventions:
//! - *Record - unencrypted messages
//! - *Body - message content after decrypting

use bc_components::{MLDSAPrivateKey, MLDSAPublicKey, MLKEMPrivateKey, MLKEMPublicKey};
use rkyv::{
    api::{
        high::{to_bytes_in, HighSerializer, HighValidator},
        low::{self, LowDeserializer},
    },
    bytecheck::CheckBytes,
    ser::allocator::ArenaHandle,
    Archive, Deserialize, Portable, Serialize,
};
use thiserror::Error;

mod codec;
pub mod encrypted;
pub mod encrypted_message;
pub mod handshake;
mod id;
pub mod pair;
mod xid;

pub(crate) use codec::*;
pub use encrypted::{
    close::SessionCloseBody,
    stream::{CloseCode, CloseTarget, StreamCloseFrame, StreamFrame},
    SessionAck, SessionBody, SessionEnvelope,
};
pub use encrypted_message::Nonce;
pub use id::{ControlId, SessionSeq, StreamId};
pub use xid::XID;

pub(crate) type WireArchiveError = rkyv::rancor::Error;

#[derive(Debug, Clone)]
pub struct QlIdentity {
    pub xid: XID,
    pub signing_private_key: MLDSAPrivateKey,
    pub signing_public_key: MLDSAPublicKey,
    pub encapsulation_private_key: MLKEMPrivateKey,
    pub encapsulation_public_key: MLKEMPublicKey,
}

impl QlIdentity {
    pub fn from_keys(
        signing_private_key: MLDSAPrivateKey,
        signing_public_key: MLDSAPublicKey,
        encapsulation_private_key: MLKEMPrivateKey,
        encapsulation_public_key: MLKEMPublicKey,
    ) -> Self {
        Self {
            xid: XID::from_signing_public_key(&signing_public_key),
            signing_private_key,
            signing_public_key,
            encapsulation_private_key,
            encapsulation_public_key,
        }
    }
}

pub trait QlCrypto {
    fn fill_random_bytes(&self, data: &mut [u8]);
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WireError {
    #[error("invalid payload")]
    InvalidPayload,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("expired")]
    Expired,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QlRecord {
    pub header: QlHeader,
    pub payload: QlPayload,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QlHeader {
    pub sender: XID,
    pub recipient: XID,
}

impl QlHeader {
    pub fn aad(&self) -> Vec<u8> {
        encode_value(self)
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlMeta {
    pub control_id: ControlId,
    pub valid_until: u64,
}

impl From<&ArchivedControlMeta> for ControlMeta {
    fn from(value: &ArchivedControlMeta) -> Self {
        Self {
            control_id: (&value.control_id).into(),
            valid_until: value.valid_until.to_native(),
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum QlPayload {
    Handshake(handshake::HandshakeRecord),
    Pair(pair::PairRequestRecord),
    Encrypted(encrypted_message::EncryptedMessage),
}

pub fn encode_record(record: &QlRecord) -> Vec<u8> {
    encode_value(record)
}

pub fn access_record(bytes: &[u8]) -> Result<&ArchivedQlRecord, WireError> {
    access_value(bytes)
}

pub fn access_record_mut(
    bytes: &mut [u8],
) -> Result<rkyv::seal::Seal<'_, ArchivedQlRecord>, WireError> {
    rkyv::access_mut::<ArchivedQlRecord, WireArchiveError>(bytes)
        .map_err(|_| WireError::InvalidPayload)
}

pub fn decode_record(bytes: &[u8]) -> Result<QlRecord, WireError> {
    deserialize_value(access_record(bytes)?)
}

pub(crate) fn encode_value(
    value: &impl for<'a> Serialize<HighSerializer<Vec<u8>, ArenaHandle<'a>, WireArchiveError>>,
) -> Vec<u8> {
    to_bytes_in::<_, WireArchiveError>(value, Vec::new())
        .expect("wire serialization should not fail")
}

pub(crate) fn access_value<T>(bytes: &[u8]) -> Result<&T, WireError>
where
    T: Portable + for<'a> CheckBytes<HighValidator<'a, WireArchiveError>>,
{
    rkyv::access::<T, WireArchiveError>(bytes).map_err(|_| WireError::InvalidPayload)
}

pub(crate) fn deserialize_value<T>(
    value: &impl rkyv::Deserialize<T, LowDeserializer<WireArchiveError>>,
) -> Result<T, WireError> {
    low::deserialize::<T, WireArchiveError>(value).map_err(|_| WireError::InvalidPayload)
}

pub(crate) fn ensure_not_expired(meta: &ControlMeta, now_seconds: u64) -> Result<(), WireError> {
    if now_seconds > meta.valid_until {
        Err(WireError::Expired)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bc_components::SymmetricKey;

    use super::*;

    #[test]
    fn ql_record_round_trip() {
        let header = QlHeader {
            sender: XID([1; XID::XID_SIZE]),
            recipient: XID([2; XID::XID_SIZE]),
        };
        let body = SessionEnvelope {
            seq: SessionSeq(7),
            ack: SessionAck {
                base: SessionSeq(3),
                bitmap: 0b101,
            },
            body: SessionBody::Ping(encrypted::ping::PingBody),
        };
        let record = encrypted::encrypt_record(
            header.clone(),
            &SymmetricKey::from_data([7; SymmetricKey::SYMMETRIC_KEY_SIZE]),
            &body,
            Nonce([8; Nonce::NONCE_SIZE]),
        );

        let bytes = encode_record(&record);
        let decoded = decode_record(&bytes).unwrap();
        assert_eq!(decoded.header, header);
        assert!(matches!(decoded.payload, QlPayload::Encrypted(_)));
    }
}
