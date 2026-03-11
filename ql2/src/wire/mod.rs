use bc_components::XID;
use dcbor::CBOR;
use rkyv::{
    api::{
        high::{to_bytes_in, HighSerializer, HighValidator},
        low::{self, LowDeserializer},
    },
    bytecheck::CheckBytes,
    ser::allocator::ArenaHandle,
    Archive, Deserialize, Portable, Serialize,
};

pub mod encrypted_message;
pub mod handshake;
pub mod heartbeat;
pub mod pair;
pub mod stream;
pub mod unpair;

mod codec;

pub(crate) use codec::*;

use self::{
    encrypted_message::EncryptedMessage, handshake::HandshakeRecord, pair::PairRequestRecord,
    unpair::UnpairRecord,
};
use crate::QlError;

pub(crate) type WireArchiveError = rkyv::rancor::Error;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QlRecord {
    pub header: QlHeader,
    pub payload: QlPayload,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QlHeader {
    #[rkyv(with = AsWireXid)]
    pub sender: XID,
    #[rkyv(with = AsWireXid)]
    pub recipient: XID,
}

impl QlHeader {
    pub fn aad(&self) -> Vec<u8> {
        encode_value(self)
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum QlPayload {
    Handshake(HandshakeRecord),
    Pair(PairRequestRecord),
    Unpair(UnpairRecord),
    Heartbeat(EncryptedMessage),
    Stream(EncryptedMessage),
}

pub fn encode_record(record: &QlRecord) -> Vec<u8> {
    encode_value(record)
}

pub fn access_record(bytes: &[u8]) -> Result<&ArchivedQlRecord, QlError> {
    access_value(bytes)
}

pub fn decode_record(bytes: &[u8]) -> Result<QlRecord, QlError> {
    deserialize_value(access_record(bytes)?)
}

pub(crate) fn encode_value(
    value: &impl for<'a> Serialize<HighSerializer<Vec<u8>, ArenaHandle<'a>, WireArchiveError>>,
) -> Vec<u8> {
    to_bytes_in::<_, WireArchiveError>(value, Vec::new())
        .expect("wire serialization should not fail")
}

pub(crate) fn access_value<T>(bytes: &[u8]) -> Result<&T, QlError>
where
    T: Portable + for<'a> CheckBytes<HighValidator<'a, WireArchiveError>>,
{
    rkyv::access::<T, WireArchiveError>(bytes).map_err(|_| QlError::InvalidPayload)
}

pub(crate) fn deserialize_value<T>(
    value: &impl rkyv::Deserialize<T, LowDeserializer<WireArchiveError>>,
) -> Result<T, QlError> {
    low::deserialize::<T, WireArchiveError>(value).map_err(|_| QlError::InvalidPayload)
}

pub(crate) fn ensure_not_expired(valid_until: u64) -> Result<(), QlError> {
    if now_secs() > valid_until {
        Err(QlError::Timeout)
    } else {
        Ok(())
    }
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[test]
fn ql_record_round_trip() {
    let record = QlRecord {
        header: QlHeader {
            sender: XID::from_data([1; XID::XID_SIZE]),
            recipient: XID::from_data([2; XID::XID_SIZE]),
        },
        payload: QlPayload::Heartbeat(encrypted_message::EncryptedMessage::encrypt(
            &bc_components::SymmetricKey::from_data(
                [7; bc_components::SymmetricKey::SYMMETRIC_KEY_SIZE],
            ),
            vec![3u8, 4, 5],
            b"roundtrip",
            [8; encrypted_message::NONCE_SIZE],
        )),
    };

    let bytes = encode_record(&record);
    let decoded = decode_record(&bytes).unwrap();

    assert_eq!(decoded, record);
}
