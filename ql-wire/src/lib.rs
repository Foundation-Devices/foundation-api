//! quantum link protocol wire format

use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

mod codec;
pub mod encrypted;
pub mod encrypted_message;
pub mod handshake;
pub mod pair;
mod pq;

pub use encrypted::{
    close::SessionCloseBody, CloseCode, CloseTarget, SessionAck, SessionBody, SessionEnvelope,
    StreamChunk, StreamClose,
};
pub use encrypted_message::{EncryptedMessage, EncryptedMessageMut, EncryptedMessageRef};
pub use pq::{
    generate_ml_dsa_keypair, generate_ml_kem_keypair, MlDsaPrivateKey, MlDsaPublicKey,
    MlDsaSignature, MlKemCiphertext, MlKemPrivateKey, MlKemPublicKey, SessionKey,
};

pub const XID_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const AUTH_SIZE: usize = 16;

pub type XID = [u8; XID_SIZE];
pub type Nonce = [u8; NONCE_SIZE];
pub type ControlId = u32;
pub type SessionSeq = u64;
pub type StreamId = u32;

#[derive(Debug, Clone)]
pub struct QlIdentity {
    pub xid: XID,
    pub signing_private_key: MlDsaPrivateKey,
    pub signing_public_key: MlDsaPublicKey,
    pub encapsulation_private_key: MlKemPrivateKey,
    pub encapsulation_public_key: MlKemPublicKey,
}

impl QlIdentity {
    pub fn from_keys(
        xid: XID,
        signing_private_key: MlDsaPrivateKey,
        signing_public_key: MlDsaPublicKey,
        encapsulation_private_key: MlKemPrivateKey,
        encapsulation_public_key: MlKemPublicKey,
    ) -> Self {
        Self {
            xid,
            signing_private_key,
            signing_public_key,
            encapsulation_private_key,
            encapsulation_public_key,
        }
    }
}

pub trait QlCrypto {
    fn fill_random_bytes(&self, data: &mut [u8]);

    fn hash(&self, parts: &[&[u8]]) -> [u8; 32];

    fn encrypt_with_aead(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Option<[u8; AUTH_SIZE]>;

    fn decrypt_with_aead(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        auth_tag: &[u8; AUTH_SIZE],
    ) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QlHeader {
    pub sender: XID,
    pub recipient: XID,
}

impl QlHeader {
    pub fn aad(&self) -> Vec<u8> {
        codec::header_aad(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlMeta {
    pub control_id: ControlId,
    pub valid_until: u64,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub(crate) struct ControlMetaWire {
    control_id: codec::U32Le,
    valid_until: codec::U64Le,
}

pub(crate) fn control_meta_to_wire(meta: &ControlMeta) -> ControlMetaWire {
    ControlMetaWire {
        control_id: codec::U32Le::new(meta.control_id),
        valid_until: codec::U64Le::new(meta.valid_until),
    }
}

pub(crate) fn control_meta_from_wire(meta: ControlMetaWire) -> ControlMeta {
    ControlMeta {
        control_id: meta.control_id.get(),
        valid_until: meta.valid_until.get(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QlRecord {
    pub header: QlHeader,
    pub payload: QlPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlPayload {
    PairRequest(pair::PairRequestRecord),
    Hello(handshake::Hello),
    HelloReply(handshake::HelloReply),
    Confirm(handshake::Confirm),
    Ready(handshake::Ready),
    Session(EncryptedMessage),
}

pub struct QlRecordRef<'a> {
    pub header: QlHeader,
    pub payload: QlPayloadRef<'a>,
}

pub enum QlPayloadRef<'a> {
    PairRequest(pair::PairRequestRecordRef<'a>),
    Hello(handshake::Hello),
    HelloReply(handshake::HelloReply),
    Confirm(handshake::Confirm),
    Ready(handshake::ReadyRef<'a>),
    Session(EncryptedMessageRef<'a>),
}

pub struct QlRecordMut<'a> {
    pub header: QlHeader,
    pub payload: QlPayloadMut<'a>,
}

pub enum QlPayloadMut<'a> {
    PairRequest(pair::PairRequestRecordMut<'a>),
    Hello(handshake::Hello),
    HelloReply(handshake::HelloReply),
    Confirm(handshake::Confirm),
    Ready(handshake::ReadyMut<'a>),
    Session(EncryptedMessageMut<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WireError {
    #[error("invalid payload")]
    InvalidPayload,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("expired")]
    Expired,
    #[error("signing failed")]
    SigningFailed,
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum RecordKind {
    PairRequest = 1,
    Hello = 2,
    HelloReply = 3,
    Confirm = 4,
    Ready = 5,
    Session = 6,
}

impl RecordKind {
    fn from_byte(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::PairRequest),
            2 => Ok(Self::Hello),
            3 => Ok(Self::HelloReply),
            4 => Ok(Self::Confirm),
            5 => Ok(Self::Ready),
            6 => Ok(Self::Session),
            _ => Err(WireError::InvalidPayload),
        }
    }

    fn for_payload(payload: &QlPayload) -> Self {
        match payload {
            QlPayload::PairRequest(_) => Self::PairRequest,
            QlPayload::Hello(_) => Self::Hello,
            QlPayload::HelloReply(_) => Self::HelloReply,
            QlPayload::Confirm(_) => Self::Confirm,
            QlPayload::Ready(_) => Self::Ready,
            QlPayload::Session(_) => Self::Session,
        }
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct QlRecordHeaderWire {
    version: u8,
    kind: u8,
    sender: [u8; XID_SIZE],
    recipient: [u8; XID_SIZE],
}

const QL_WIRE_VERSION: u8 = 1;

impl QlRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let header = QlRecordHeaderWire {
            version: QL_WIRE_VERSION,
            kind: RecordKind::for_payload(&self.payload) as u8,
            sender: self.header.sender,
            recipient: self.header.recipient,
        };
        codec::push_value(&mut out, &header);
        match &self.payload {
            QlPayload::PairRequest(request) => request.encode_into(&mut out),
            QlPayload::Hello(hello) => hello.encode_into(&mut out),
            QlPayload::HelloReply(reply) => reply.encode_into(&mut out),
            QlPayload::Confirm(confirm) => confirm.encode_into(&mut out),
            QlPayload::Ready(ready) => ready.encode_into(&mut out),
            QlPayload::Session(encrypted) => encrypted.encode_into(&mut out),
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(Self::parse(bytes)?.to_owned())
    }

    pub fn parse(bytes: &[u8]) -> Result<QlRecordRef<'_>, WireError> {
        let (header, payload_bytes) = decode_record_header(bytes)?;
        let payload = parse_payload_ref(header.kind, payload_bytes)?;
        Ok(QlRecordRef {
            header: header.header,
            payload,
        })
    }

    pub fn parse_mut(bytes: &mut [u8]) -> Result<QlRecordMut<'_>, WireError> {
        let (header, payload_bytes) = decode_record_header_mut(bytes)?;
        let payload = parse_payload_mut(header.kind, payload_bytes)?;
        Ok(QlRecordMut {
            header: header.header,
            payload,
        })
    }
}

impl<'a> QlRecordRef<'a> {
    pub fn to_owned(&self) -> QlRecord {
        QlRecord {
            header: self.header,
            payload: self.payload.to_owned(),
        }
    }
}

impl<'a> QlPayloadRef<'a> {
    pub fn to_owned(&self) -> QlPayload {
        match self {
            Self::PairRequest(request) => QlPayload::PairRequest(request.to_pair_request_record()),
            Self::Hello(hello) => QlPayload::Hello(hello.clone()),
            Self::HelloReply(reply) => QlPayload::HelloReply(reply.clone()),
            Self::Confirm(confirm) => QlPayload::Confirm(confirm.clone()),
            Self::Ready(ready) => QlPayload::Ready(handshake::Ready {
                encrypted: ready.to_encrypted_message(),
            }),
            Self::Session(encrypted) => QlPayload::Session(encrypted.to_encrypted_message()),
        }
    }
}

impl<'a> QlRecordMut<'a> {
    pub fn to_owned(&self) -> QlRecord {
        QlRecord {
            header: self.header,
            payload: self.payload.to_owned(),
        }
    }
}

impl<'a> QlPayloadMut<'a> {
    pub fn to_owned(&self) -> QlPayload {
        match self {
            Self::PairRequest(request) => QlPayload::PairRequest(request.to_pair_request_record()),
            Self::Hello(hello) => QlPayload::Hello(hello.clone()),
            Self::HelloReply(reply) => QlPayload::HelloReply(reply.clone()),
            Self::Confirm(confirm) => QlPayload::Confirm(confirm.clone()),
            Self::Ready(ready) => QlPayload::Ready(handshake::Ready {
                encrypted: ready.to_encrypted_message(),
            }),
            Self::Session(encrypted) => QlPayload::Session(encrypted.to_encrypted_message()),
        }
    }
}

pub(crate) fn ensure_not_expired(meta: &ControlMeta, now_seconds: u64) -> Result<(), WireError> {
    if now_seconds > meta.valid_until {
        Err(WireError::Expired)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct DecodedRecordHeader {
    kind: RecordKind,
    header: QlHeader,
}

fn decode_record_header(bytes: &[u8]) -> Result<(DecodedRecordHeader, &[u8]), WireError> {
    let (wire, payload_bytes) = codec::read_prefix::<QlRecordHeaderWire>(bytes)?;
    if wire.version != QL_WIRE_VERSION {
        return Err(WireError::InvalidPayload);
    }
    Ok((
        DecodedRecordHeader {
            kind: RecordKind::from_byte(wire.kind)?,
            header: QlHeader {
                sender: wire.sender,
                recipient: wire.recipient,
            },
        },
        payload_bytes,
    ))
}

fn decode_record_header_mut(
    bytes: &mut [u8],
) -> Result<(DecodedRecordHeader, &mut [u8]), WireError> {
    let (wire, payload_bytes) = codec::read_prefix_mut::<QlRecordHeaderWire>(bytes)?;
    if wire.version != QL_WIRE_VERSION {
        return Err(WireError::InvalidPayload);
    }
    Ok((
        DecodedRecordHeader {
            kind: RecordKind::from_byte(wire.kind)?,
            header: QlHeader {
                sender: wire.sender,
                recipient: wire.recipient,
            },
        },
        payload_bytes,
    ))
}

fn parse_payload_ref<'a>(
    kind: RecordKind,
    payload: &'a [u8],
) -> Result<QlPayloadRef<'a>, WireError> {
    match kind {
        RecordKind::PairRequest => Ok(QlPayloadRef::PairRequest(
            pair::PairRequestRecordWire::parse(payload)?,
        )),
        RecordKind::Hello => Ok(QlPayloadRef::Hello(handshake::Hello::decode(payload)?)),
        RecordKind::HelloReply => Ok(QlPayloadRef::HelloReply(handshake::HelloReply::decode(
            payload,
        )?)),
        RecordKind::Confirm => Ok(QlPayloadRef::Confirm(handshake::Confirm::decode(payload)?)),
        RecordKind::Ready => Ok(QlPayloadRef::Ready(
            encrypted_message::EncryptedMessageWire::parse(payload)?,
        )),
        RecordKind::Session => Ok(QlPayloadRef::Session(
            encrypted_message::EncryptedMessageWire::parse(payload)?,
        )),
    }
}

fn parse_payload_mut<'a>(
    kind: RecordKind,
    payload: &'a mut [u8],
) -> Result<QlPayloadMut<'a>, WireError> {
    match kind {
        RecordKind::PairRequest => Ok(QlPayloadMut::PairRequest(
            pair::PairRequestRecordWire::parse_mut(payload)?,
        )),
        RecordKind::Hello => Ok(QlPayloadMut::Hello(handshake::Hello::decode(payload)?)),
        RecordKind::HelloReply => Ok(QlPayloadMut::HelloReply(handshake::HelloReply::decode(
            payload,
        )?)),
        RecordKind::Confirm => Ok(QlPayloadMut::Confirm(handshake::Confirm::decode(payload)?)),
        RecordKind::Ready => Ok(QlPayloadMut::Ready(
            encrypted_message::EncryptedMessageWire::parse_mut(payload)?,
        )),
        RecordKind::Session => Ok(QlPayloadMut::Session(
            encrypted_message::EncryptedMessageWire::parse_mut(payload)?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};

    use libcrux_aesgcm::AesGcm256Key;
    use sha2::{Digest, Sha256};

    use super::*;

    struct TestCrypto(AtomicU8);

    impl TestCrypto {
        fn new(seed: u8) -> Self {
            Self(AtomicU8::new(seed))
        }
    }

    impl QlCrypto for TestCrypto {
        fn fill_random_bytes(&self, data: &mut [u8]) {
            let seed = self.0.fetch_add(1, Ordering::Relaxed);
            for (index, byte) in data.iter_mut().enumerate() {
                *byte = seed.wrapping_add(index as u8);
            }
        }

        fn hash(&self, parts: &[&[u8]]) -> [u8; 32] {
            let mut hasher = Sha256::new();
            for part in parts {
                hasher.update(part);
            }
            hasher.finalize().into()
        }

        fn encrypt_with_aead(
            &self,
            key: &SessionKey,
            nonce: &Nonce,
            aad: &[u8],
            buffer: &mut [u8],
        ) -> Option<[u8; AUTH_SIZE]> {
            let key: AesGcm256Key = (*key.data()).into();
            let plaintext = buffer.to_vec();
            let mut auth = [0u8; AUTH_SIZE];
            key.encrypt(buffer, (&mut auth).into(), nonce.into(), aad, &plaintext)
                .ok()?;
            Some(auth)
        }

        fn decrypt_with_aead(
            &self,
            key: &SessionKey,
            nonce: &Nonce,
            aad: &[u8],
            buffer: &mut [u8],
            auth_tag: &[u8; AUTH_SIZE],
        ) -> bool {
            let key: AesGcm256Key = (*key.data()).into();
            let ciphertext = buffer.to_vec();
            key.decrypt(buffer, nonce.into(), aad, &ciphertext, auth_tag.into())
                .is_ok()
        }
    }

    #[test]
    fn encrypted_session_record_round_trip_and_decrypt() {
        let crypto = TestCrypto::new(1);
        let header = QlHeader {
            sender: [1; XID_SIZE],
            recipient: [2; XID_SIZE],
        };
        let body = SessionEnvelope {
            seq: 7,
            ack: SessionAck {
                base: 3,
                bitmap: 0b101,
            },
            body: SessionBody::Stream(StreamChunk {
                stream_id: 9,
                offset: 11,
                bytes: b"hello".to_vec(),
                fin: true,
            }),
        };
        let session_key = SessionKey::from_data([7; SessionKey::SIZE]);
        let record =
            encrypted::encrypt_record(&crypto, header, &session_key, &body, [8; NONCE_SIZE])
                .unwrap();

        let bytes = record.encode();
        let decoded = QlRecord::decode(&bytes).unwrap();
        assert_eq!(decoded.header, header);
        assert!(matches!(decoded.payload, QlPayload::Session(_)));

        let parsed = QlRecord::parse(&bytes).unwrap();
        assert_eq!(parsed.to_owned(), record);

        let mut bytes = bytes;
        let QlRecordMut { header, payload } = QlRecord::parse_mut(&mut bytes).unwrap();
        let QlPayloadMut::Session(mut encrypted) = payload else {
            panic!("expected session payload");
        };
        let decrypted =
            encrypted::decrypt_record(&crypto, &header, &mut encrypted, &session_key).unwrap();
        assert_eq!(decrypted.to_session_envelope().unwrap(), body);
    }

    #[test]
    fn pair_request_round_trip_and_decrypt() {
        let crypto = TestCrypto::new(9);
        let sender_signing = generate_ml_dsa_keypair(&crypto);
        let sender_kem = generate_ml_kem_keypair(&crypto);
        let recipient_signing = generate_ml_dsa_keypair(&crypto);
        let recipient_kem = generate_ml_kem_keypair(&crypto);

        let sender = QlIdentity::from_keys(
            [3; XID_SIZE],
            sender_signing.0,
            sender_signing.1,
            sender_kem.0,
            sender_kem.1,
        );
        let recipient = QlIdentity::from_keys(
            [4; XID_SIZE],
            recipient_signing.0,
            recipient_signing.1,
            recipient_kem.0,
            recipient_kem.1,
        );
        let meta = ControlMeta {
            control_id: 55,
            valid_until: 999,
        };
        let record = pair::build_pair_request(
            &crypto,
            &sender,
            recipient.xid,
            &recipient.encapsulation_public_key,
            meta,
        )
        .unwrap();

        let mut bytes = record.encode();
        let QlRecordMut { header, payload } = QlRecord::parse_mut(&mut bytes).unwrap();
        let QlPayloadMut::PairRequest(mut request) = payload else {
            panic!("expected pair request");
        };
        let body =
            pair::decrypt_pair_request(&crypto, &recipient, &header, &mut request, 100).unwrap();
        assert_eq!(body.meta, meta);
        assert_eq!(body.xid, sender.xid);
        assert_eq!(body.signing_pub_key, sender.signing_public_key);
        assert_eq!(body.encapsulation_pub_key, sender.encapsulation_public_key);
    }

    #[test]
    fn ready_round_trip_and_decrypt() {
        let crypto = TestCrypto::new(30);
        let header = QlHeader {
            sender: [5; XID_SIZE],
            recipient: [6; XID_SIZE],
        };
        let session_key = SessionKey::from_data([11; SessionKey::SIZE]);
        let meta = ControlMeta {
            control_id: 77,
            valid_until: 500,
        };
        let ready =
            handshake::build_ready(&crypto, header, &session_key, meta, [12; NONCE_SIZE]).unwrap();
        let record = QlRecord {
            header,
            payload: QlPayload::Ready(ready),
        };

        let mut bytes = record.encode();
        let parsed = QlRecord::decode(&bytes).unwrap();
        assert_eq!(parsed, record);

        let QlRecordMut { header, payload } = QlRecord::parse_mut(&mut bytes).unwrap();
        let QlPayloadMut::Ready(mut ready) = payload else {
            panic!("expected ready payload");
        };
        let body =
            handshake::decrypt_ready(&crypto, &header, &mut ready, &session_key, 100).unwrap();
        assert_eq!(body.meta, meta);
    }
}
