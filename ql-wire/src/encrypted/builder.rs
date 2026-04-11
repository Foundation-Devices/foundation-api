use bytes::BufMut;

use super::{RecordAck, SessionClose, SessionFrame, StreamClose, StreamData, StreamWindow};
use crate::{
    BufView, ConnectionId, Nonce, QlCrypto, RecordSeq, RecordType, SessionHeader, SessionKey,
    VarInt, WireEncode, QL_WIRE_VERSION,
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
        self.push_frame_payload(super::SessionFrameKind::Ack, ack)
    }

    pub fn push_stream_data<B: BufView>(&mut self, frame: &StreamData<B>) -> bool {
        self.push_len_prefixed_frame(super::SessionFrameKind::StreamData, frame)
    }

    pub fn push_stream_window(&mut self, frame: &StreamWindow) -> bool {
        self.push_frame_payload(super::SessionFrameKind::StreamWindow, frame)
    }

    pub fn push_stream_close(&mut self, frame: &StreamClose) -> bool {
        self.push_frame_payload(super::SessionFrameKind::StreamClose, frame)
    }

    pub fn push_close(&mut self, close: &SessionClose) -> bool {
        self.push_frame_payload(super::SessionFrameKind::Close, close)
    }

    pub fn push_frame<B: BufView>(&mut self, frame: &SessionFrame<B>) -> bool {
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

        let mut prefix = &mut self.bytes[..self.prefix_len];
        prefix[0] = QL_WIRE_VERSION;
        prefix[1] = RecordType::Session as u8;
        prefix = &mut prefix[2..];
        header.encode(&mut prefix);
        auth.encode(&mut prefix);
        debug_assert!(prefix.is_empty());
        self.bytes
    }

    fn push_wire_size(&mut self, wire_size: usize, encode: impl FnOnce(&mut Vec<u8>)) -> bool {
        if !self.can_push_len(wire_size) {
            return false;
        }
        self.ensure_prefix_capacity(wire_size);
        let start = self.bytes.len();
        encode(&mut self.bytes);
        debug_assert_eq!(self.bytes.len(), start + wire_size);
        true
    }

    fn push_empty_frame(&mut self, kind: super::SessionFrameKind) -> bool {
        self.push_wire_size(1, |out| out.put_u8(kind as u8))
    }

    fn push_frame_payload<T: WireEncode + ?Sized>(
        &mut self,
        kind: super::SessionFrameKind,
        payload: &T,
    ) -> bool {
        let payload_wire_size = payload.encoded_len();
        self.push_wire_size(1 + payload_wire_size, |out| {
            out.put_u8(kind as u8);
            payload.encode(out);
        })
    }

    fn push_len_prefixed_frame<T: WireEncode + ?Sized>(
        &mut self,
        kind: super::SessionFrameKind,
        payload: &T,
    ) -> bool {
        let payload_wire_size = payload.encoded_len();
        let Ok(prefix_len) = VarInt::try_from(payload_wire_size) else {
            return false;
        };
        self.push_wire_size(1 + prefix_len.encoded_len() + payload_wire_size, |out| {
            out.put_u8(kind as u8);
            prefix_len.encode(out);
            payload.encode(out);
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
