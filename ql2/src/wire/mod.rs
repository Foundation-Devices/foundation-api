//! quantum link protocol wire format
//!
//! naming conventions:
//! - *Record - unencrypted messages
//! - *Body - message content after decrypting
//!

use bc_components::XID;
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
mod id;
pub mod pair;
pub mod seq;
pub mod stream;
pub mod unpair;

pub use id::*;
pub use seq::StreamSeq;

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

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlMeta {
    pub packet_id: PacketId,
    pub valid_until: u64,
}

impl From<&ArchivedControlMeta> for ControlMeta {
    fn from(value: &ArchivedControlMeta) -> Self {
        Self {
            packet_id: (&value.packet_id).into(),
            valid_until: value.valid_until.to_native(),
        }
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::{engine::QlCrypto, identity::QlIdentity};

    struct SizeTestCrypto(std::sync::atomic::AtomicU8);

    impl SizeTestCrypto {
        fn new(seed: u8) -> Self {
            Self(std::sync::atomic::AtomicU8::new(seed))
        }
    }

    impl QlCrypto for SizeTestCrypto {
        fn fill_random_bytes(&self, data: &mut [u8]) {
            let seed = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            for (index, byte) in data.iter_mut().enumerate() {
                *byte = seed.wrapping_add(index as u8);
            }
        }
    }

    fn size_test_identity() -> QlIdentity {
        use bc_components::{MLDSA, MLKEM};

        let (signing_private_key, signing_public_key) = MLDSA::MLDSA44.keypair();
        let (encapsulation_private_key, encapsulation_public_key) = MLKEM::MLKEM512.keypair();
        QlIdentity::from_keys(
            signing_private_key,
            signing_public_key,
            encapsulation_private_key,
            encapsulation_public_key,
        )
    }

    fn size_test_meta(packet_id: u32) -> ControlMeta {
        ControlMeta {
            packet_id: PacketId(packet_id),
            valid_until: now_secs().saturating_add(60),
        }
    }

    /*
    #[test]
    fn protocol_record_size_breakdown() {
        use crate::{
            wire::{handshake::HandshakeRecord, heartbeat::HeartbeatBody},
            StreamId,
        };

        let identity_a = size_test_identity();
        let identity_b = size_test_identity();
        let crypto_a = SizeTestCrypto::new(1);
        let crypto_b = SizeTestCrypto::new(2);

        let initiator = identity_a.xid;
        let responder = identity_b.xid;

        let (hello, initiator_secret) = handshake::build_hello(
            &identity_a,
            &crypto_a,
            responder,
            &identity_b.encapsulation_public_key,
            size_test_meta(1),
        )
        .unwrap();
        let hello_record = QlRecord {
            header: QlHeader {
                sender: initiator,
                recipient: responder,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Hello(hello.clone())),
        };
        let hello_size = encode_record(&hello_record).len();
        let hello_bytes = encode_value(&hello);
        let hello_view = access_value::<handshake::ArchivedHello>(&hello_bytes).unwrap();

        let (hello_reply, responder_secrets) = handshake::respond_hello(
            &identity_b,
            &crypto_b,
            initiator,
            &identity_a.signing_public_key,
            &identity_a.encapsulation_public_key,
            hello_view,
            size_test_meta(2),
        )
        .unwrap();
        let reply_record = QlRecord {
            header: QlHeader {
                sender: responder,
                recipient: initiator,
            },
            payload: QlPayload::Handshake(HandshakeRecord::HelloReply(hello_reply.clone())),
        };
        let reply_size = encode_record(&reply_record).len();
        let reply_bytes = encode_value(&hello_reply);
        let reply_view = access_value::<handshake::ArchivedHelloReply>(&reply_bytes).unwrap();

        let (confirm, session_key) = handshake::build_confirm(
            &identity_a,
            responder,
            &identity_b.signing_public_key,
            &hello,
            reply_view,
            &initiator_secret,
            size_test_meta(3),
        )
        .unwrap();
        let confirm_size = encode_record(&QlRecord {
            header: QlHeader {
                sender: initiator,
                recipient: responder,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Confirm(confirm.clone())),
        })
        .len();

        let confirm_bytes = encode_value(&confirm);
        let confirm_view = access_value::<handshake::ArchivedConfirm>(&confirm_bytes).unwrap();
        let _session_key_b = handshake::finalize_confirm(
            initiator,
            responder,
            &identity_a.signing_public_key,
            &hello,
            &hello_reply,
            confirm_view,
            &responder_secrets,
        )
        .unwrap();

        let pair_size = encode_record(
            &pair::build_pair_request(
                &identity_a,
                &crypto_a,
                responder,
                &identity_b.encapsulation_public_key,
                size_test_meta(11),
            )
            .unwrap(),
        )
        .len();

        let heartbeat_size = encode_record(&heartbeat::encrypt_heartbeat(
            QlHeader {
                sender: initiator,
                recipient: responder,
            },
            &session_key,
            HeartbeatBody {
                meta: size_test_meta(12),
            },
            [12; encrypted_message::NONCE_SIZE],
        ))
        .len();

        let unpair_size = encode_record(&unpair::build_unpair_record(
            &identity_a,
            QlHeader {
                sender: initiator,
                recipient: responder,
            },
            size_test_meta(13),
        ))
        .len();

        let stream_header = QlHeader {
            sender: initiator,
            recipient: responder,
        };
        let stream_record_size = |body: &stream::StreamBody, nonce: u8| {
            encode_record(&stream::encrypt_stream(
                stream_header.clone(),
                &session_key,
                body,
                [nonce; encrypted_message::NONCE_SIZE],
            ))
            .len()
        };

        let stream_ack_body = stream::StreamBody::Ack(stream::StreamAckBody {
            stream_id: StreamId(2),
            ack: stream::StreamAck {
                base: StreamSeq(19),
                bitmap: 0b0000_0110,
            },
            valid_until: now_secs().saturating_add(60),
        });
        let stream_ack_record = stream::encrypt_stream(
            stream_header.clone(),
            &session_key,
            &stream_ack_body,
            [20; encrypted_message::NONCE_SIZE],
        );
        let stream_ack_encrypted = match &stream_ack_record.payload {
            QlPayload::Stream(encrypted) => encrypted,
            _ => unreachable!(),
        };
        let stream_ack_header_size = encode_value(&stream_header).len();
        let stream_ack_body_size = encode_value(&stream_ack_body).len();
        let stream_ack_envelope_size = encode_value(stream_ack_encrypted).len();
        let stream_ack_payload_size = encode_value(&stream_ack_record.payload).len();

        let stream_open_body = stream::StreamBody::Message(stream::StreamMessage {
            tx_seq: StreamSeq(21),
            ack: stream::StreamAck::EMPTY,
            valid_until: now_secs().saturating_add(60),
            frame: stream::StreamFrame::Open(stream::StreamFrameOpen {
                stream_id: StreamId(2),
                request_head: vec![1, 2, 3],
                request_prefix: Some(stream::BodyChunk {
                    bytes: vec![9, 9, 9],
                    fin: false,
                }),
            }),
        });
        let stream_open_body_size = encode_value(&stream_open_body).len();

        let stream_message_no_ack = stream::StreamBody::Message(stream::StreamMessage {
            tx_seq: StreamSeq(20),
            ack: stream::StreamAck::EMPTY,
            valid_until: now_secs().saturating_add(60),
            frame: stream::StreamFrame::Data(stream::StreamFrameData {
                stream_id: StreamId(2),
                dir: stream::Direction::Request,
                chunk: stream::BodyChunk {
                    bytes: vec![7, 8, 9, 10],
                    fin: false,
                },
            }),
        });
        let stream_message_with_ack = stream::StreamBody::Message(stream::StreamMessage {
            tx_seq: StreamSeq(20),
            ack: stream::StreamAck {
                base: StreamSeq(19),
                bitmap: 0b0000_0110,
            },
            valid_until: now_secs().saturating_add(60),
            frame: stream::StreamFrame::Data(stream::StreamFrameData {
                stream_id: StreamId(2),
                dir: stream::Direction::Request,
                chunk: stream::BodyChunk {
                    bytes: vec![7, 8, 9, 10],
                    fin: false,
                },
            }),
        });

        let stream_ack_size = stream_record_size(&stream_ack_body, 20);
        let stream_open_size = stream_record_size(&stream_open_body, 21);
        let stream_accept_size = stream_record_size(
            &stream::StreamBody::Message(stream::StreamMessage {
                tx_seq: StreamSeq(22),
                ack: stream::StreamAck::EMPTY,
                valid_until: now_secs().saturating_add(60),
                frame: stream::StreamFrame::Accept(stream::StreamFrameAccept {
                    stream_id: StreamId(2),
                    response_head: vec![4, 5, 6],
                    response_prefix: Some(stream::BodyChunk {
                        bytes: vec![1, 2],
                        fin: false,
                    }),
                }),
            }),
            22,
        );
        let stream_reject_size = stream_record_size(
            &stream::StreamBody::Message(stream::StreamMessage {
                tx_seq: StreamSeq(23),
                ack: stream::StreamAck::EMPTY,
                valid_until: now_secs().saturating_add(60),
                frame: stream::StreamFrame::Reject(stream::StreamFrameReject {
                    stream_id: StreamId(2),
                    code: stream::RejectCode::InvalidHead,
                }),
            }),
            23,
        );
        let stream_data_no_ack_size = stream_record_size(&stream_message_no_ack, 24);
        let stream_data_with_ack_size = stream_record_size(&stream_message_with_ack, 25);
        let stream_fin_size = stream_record_size(
            &stream::StreamBody::Message(stream::StreamMessage {
                tx_seq: StreamSeq(26),
                ack: stream::StreamAck::EMPTY,
                valid_until: now_secs().saturating_add(60),
                frame: stream::StreamFrame::Data(stream::StreamFrameData {
                    stream_id: StreamId(2),
                    dir: stream::Direction::Response,
                    chunk: stream::BodyChunk {
                        bytes: Vec::new(),
                        fin: true,
                    },
                }),
            }),
            26,
        );
        let stream_reset_size = stream_record_size(
            &stream::StreamBody::Message(stream::StreamMessage {
                tx_seq: StreamSeq(27),
                ack: stream::StreamAck::EMPTY,
                valid_until: now_secs().saturating_add(60),
                frame: stream::StreamFrame::Reset(stream::StreamFrameReset {
                    stream_id: StreamId(2),
                    target: stream::ResetTarget::Both,
                    code: stream::ResetCode::Protocol,
                }),
            }),
            27,
        );

        let print_size = |label: &str, size: usize| {
            println!("{label:<28}: {size} bytes");
        };

        print_size("ql2 size hello", hello_size);
        print_size("ql2 size hello_reply", reply_size);
        print_size("ql2 size confirm", confirm_size);
        print_size("ql2 size pair", pair_size);
        print_size("ql2 size heartbeat", heartbeat_size);
        print_size("ql2 size unpair", unpair_size);
        print_size("ql2 size stream ack-only", stream_ack_size);
        print_size("ql2 size stream open", stream_open_size);
        print_size("ql2 size stream accept", stream_accept_size);
        print_size("ql2 size stream reject", stream_reject_size);
        print_size("ql2 size stream data no ack", stream_data_no_ack_size);
        print_size("ql2 size stream data w/ ack", stream_data_with_ack_size);
        print_size("ql2 size stream fin", stream_fin_size);
        print_size("ql2 size stream reset", stream_reset_size);
        println!(
        "ql2 stream ack breakdown     : header={} aad={} plaintext={} envelope={} payload={} full={}",
        stream_ack_header_size,
        stream_header.aad().len(),
        stream_ack_body_size,
        stream_ack_envelope_size,
        stream_ack_payload_size,
        stream_ack_size,
    );
        println!(
            "ql2 stream open delta        : open_body={} ack_body={} (+{} bytes)",
            stream_open_body_size,
            stream_ack_body_size,
            stream_open_body_size.saturating_sub(stream_ack_body_size),
        );
        println!(
            "ql2 stream data ack delta    : no_ack={} with_ack={} (+{} bytes)",
            stream_data_no_ack_size,
            stream_data_with_ack_size,
            stream_data_with_ack_size.saturating_sub(stream_data_no_ack_size),
        );

        assert!(hello_size > 0);
        assert!(reply_size > 0);
        assert!(confirm_size > 0);
        assert!(pair_size > 0);
        assert!(heartbeat_size > 0);
        assert!(unpair_size > 0);
        assert!(stream_ack_size > 0);
        assert!(stream_open_size > 0);
        assert!(stream_accept_size > 0);
        assert!(stream_reject_size > 0);
        assert!(stream_data_no_ack_size > 0);
        assert!(stream_data_with_ack_size > 0);
        assert!(stream_fin_size > 0);
        assert!(stream_reset_size > 0);
    }
    */
}
