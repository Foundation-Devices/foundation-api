use super::{RecordAck, SessionClose, SessionFrame, StreamClose, StreamData, StreamWindow};
use crate::{
    codec, ByteChunks, ConnectionId, Nonce, QlCrypto, RecordSeq, RecordType, SessionHeader,
    SessionKey, VarInt, QL_WIRE_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecordBuilder {
    seq: RecordSeq,
    prefix_len: usize,
    max_capacity: usize,
    bytes: Vec<u8>,
}

impl SessionRecordBuilder {
    pub const MIN_CAPACITY: usize = 1
        + 1
        + ConnectionId::SIZE
        + RecordSeq::MAX_ENCODED_LEN
        + crate::ENCRYPTED_MESSAGE_AUTH_SIZE;

    pub fn new(seq: RecordSeq, max_capacity: usize) -> Self {
        let prefix_len =
            1 + 1 + ConnectionId::SIZE + seq.encoded_len() + crate::ENCRYPTED_MESSAGE_AUTH_SIZE;
        assert!(max_capacity >= prefix_len);
        Self {
            seq,
            prefix_len,
            max_capacity,
            bytes: Vec::new(),
        }
    }

    pub fn seq(&self) -> RecordSeq {
        self.seq
    }

    pub fn prefix_len(&self) -> usize {
        self.prefix_len
    }

    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    pub fn len(&self) -> usize {
        self.bytes.len().saturating_sub(self.prefix_len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn remaining_capacity(&self) -> usize {
        self.max_capacity
            .saturating_sub(self.bytes.len().max(self.prefix_len))
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.get(self.prefix_len..).unwrap_or_default()
    }

    pub fn push_ping(&mut self) -> bool {
        self.push_empty_frame(super::SessionFrameKind::Ping)
    }

    pub fn push_ack(&mut self, ack: &RecordAck) -> bool {
        self.push_frame_payload(super::SessionFrameKind::Ack, ack.wire_size(), |payload| {
            ack.encode_into(payload);
        })
    }

    pub fn push_stream_data<B: ByteChunks>(&mut self, frame: &StreamData<B>) -> bool {
        self.push_len_prefixed_frame(
            super::SessionFrameKind::StreamData,
            frame.wire_size(),
            |payload| {
                frame.encode_into(payload);
            },
        )
    }

    pub fn push_stream_window(&mut self, frame: &StreamWindow) -> bool {
        self.push_frame_payload(
            super::SessionFrameKind::StreamWindow,
            frame.wire_size(),
            |payload| {
                frame.encode_into(payload);
            },
        )
    }

    pub fn push_stream_close(&mut self, frame: &StreamClose) -> bool {
        self.push_frame_payload(
            super::SessionFrameKind::StreamClose,
            frame.wire_size(),
            |payload| {
                frame.encode_into(payload);
            },
        )
    }

    pub fn push_close(&mut self, close: &SessionClose) -> bool {
        self.push_frame_payload(
            super::SessionFrameKind::Close,
            SessionClose::WIRE_SIZE,
            |payload| {
                close.encode_into(payload);
            },
        )
    }

    pub fn push_frame<B: ByteChunks>(&mut self, frame: &SessionFrame<B>) -> bool {
        match frame {
            SessionFrame::Ping => self.push_ping(),
            SessionFrame::Ack(frame) => self.push_ack(frame),
            SessionFrame::StreamData(frame) => self.push_stream_data(frame),
            SessionFrame::StreamWindow(frame) => self.push_stream_window(frame),
            SessionFrame::StreamClose(frame) => self.push_stream_close(frame),
            SessionFrame::Close(close) => self.push_close(close),
        }
    }

    pub fn encrypt(
        mut self,
        crypto: &impl QlCrypto,
        connection_id: ConnectionId,
        session_key: &SessionKey,
    ) -> Vec<u8> {
        self.ensure_prefix_capacity(0);
        let header = SessionHeader {
            connection_id,
            seq: self.seq,
        };
        let aad = header.aad();
        let nonce = Nonce::from_counter(self.seq.into_inner());
        let auth = crypto.aes256_gcm_encrypt(
            session_key,
            &nonce,
            &aad,
            &mut self.bytes[self.prefix_len..],
        );

        let prefix = &mut self.bytes[..self.prefix_len];
        prefix[0] = QL_WIRE_VERSION;
        prefix[1] = RecordType::Session as u8;
        let auth_out = header.encode_into(&mut prefix[2..]);
        auth_out[..crate::ENCRYPTED_MESSAGE_AUTH_SIZE].copy_from_slice(&auth);
        self.bytes
    }

    fn push_wire_size(&mut self, wire_size: usize, encode: impl FnOnce(&mut [u8])) -> bool {
        if !self.can_push_len(wire_size) {
            return false;
        }
        self.ensure_prefix_capacity(wire_size);
        let start = self.bytes.len();
        self.bytes.resize(start + wire_size, 0);
        encode(&mut self.bytes[start..]);
        true
    }

    fn push_empty_frame(&mut self, kind: super::SessionFrameKind) -> bool {
        self.push_wire_size(1, |out| out[0] = kind as u8)
    }

    fn push_frame_payload(
        &mut self,
        kind: super::SessionFrameKind,
        payload_wire_size: usize,
        encode_payload: impl FnOnce(&mut [u8]),
    ) -> bool {
        self.push_wire_size(1 + payload_wire_size, |out| {
            out[0] = kind as u8;
            encode_payload(&mut out[1..]);
        })
    }

    fn push_len_prefixed_frame(
        &mut self,
        kind: super::SessionFrameKind,
        payload_wire_size: usize,
        encode_payload: impl FnOnce(&mut [u8]),
    ) -> bool {
        let Ok(prefix_len) = VarInt::try_from(payload_wire_size) else {
            return false;
        };
        self.push_wire_size(1 + prefix_len.size() + payload_wire_size, |out| {
            out[0] = kind as u8;
            let payload = codec::write_varint(&mut out[1..], prefix_len);
            encode_payload(payload);
        })
    }

    fn can_push_len(&self, len: usize) -> bool {
        len <= self.remaining_capacity()
    }

    fn ensure_prefix_capacity(&mut self, additional_body_len: usize) {
        if self.bytes.is_empty() {
            self.bytes.reserve(self.prefix_len + additional_body_len);
            self.bytes.resize(self.prefix_len, 0);
        }
    }
}
