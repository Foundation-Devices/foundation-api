use super::{RecordAck, SessionClose, SessionFrame, StreamClose, StreamData, StreamWindow};
use crate::{ByteChunks, Nonce, QlCrypto, RecordType, SessionHeader, SessionKey, QL_WIRE_VERSION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecordBuilder {
    max_capacity: usize,
    bytes: Vec<u8>,
}

impl SessionRecordBuilder {
    pub const WIRE_PREFIX_LEN: usize =
        1 + 1 + SessionHeader::WIRE_SIZE + crate::ENCRYPTED_MESSAGE_AUTH_SIZE;

    pub fn new(max_capacity: usize) -> Self {
        assert!(max_capacity >= Self::WIRE_PREFIX_LEN);
        Self {
            max_capacity,
            bytes: Vec::new(),
        }
    }

    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    pub fn len(&self) -> usize {
        self.bytes.len().saturating_sub(Self::WIRE_PREFIX_LEN)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn remaining_capacity(&self) -> usize {
        self.max_capacity
            .saturating_sub(self.bytes.len().max(Self::WIRE_PREFIX_LEN))
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.get(Self::WIRE_PREFIX_LEN..).unwrap_or_default()
    }

    pub fn push_ping(&mut self) -> bool {
        self.push_wire_size(1, |out| out[0] = super::SessionFrameKind::Ping as u8)
    }

    pub fn push_ack(&mut self, ack: &RecordAck) -> bool {
        let len = 1 + RecordAck::WIRE_SIZE;
        self.push_wire_size(len, |out| {
            out[0] = super::SessionFrameKind::Ack as u8;
            ack.encode_into(&mut out[1..]);
        })
    }

    pub fn push_stream_data<B: ByteChunks>(&mut self, frame: &StreamData<B>) -> bool {
        let len = 1 + super::SIZE_LEN + frame.wire_size();
        self.push_wire_size(len, |out| {
            out[0] = super::SessionFrameKind::StreamData as u8;
            super::push_variable_len(&mut out[1..=super::SIZE_LEN], frame.wire_size());
            frame.encode_into(&mut out[1 + super::SIZE_LEN..]);
        })
    }

    pub fn push_stream_window(&mut self, frame: &StreamWindow) -> bool {
        let len = 1 + StreamWindow::WIRE_SIZE;
        self.push_wire_size(len, |out| {
            out[0] = super::SessionFrameKind::StreamWindow as u8;
            frame.encode_into(&mut out[1..]);
        })
    }

    pub fn push_stream_close(&mut self, frame: &StreamClose) -> bool {
        let len = 1 + super::SIZE_LEN + StreamClose::WIRE_SIZE;
        self.push_wire_size(len, |out| {
            out[0] = super::SessionFrameKind::StreamClose as u8;
            super::push_variable_len(&mut out[1..=super::SIZE_LEN], StreamClose::WIRE_SIZE);
            frame.encode_into(&mut out[1 + super::SIZE_LEN..]);
        })
    }

    pub fn push_close(&mut self, close: &SessionClose) -> bool {
        let len = 1 + SessionClose::WIRE_SIZE;
        self.push_wire_size(len, |out| {
            out[0] = super::SessionFrameKind::Close as u8;
            close.encode_into(&mut out[1..]);
        })
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
        header: SessionHeader,
        session_key: &SessionKey,
    ) -> Vec<u8> {
        self.ensure_prefix_capacity(0);
        let aad = header.aad();
        let nonce = Nonce::from_counter(header.seq.0);
        let auth = crypto.aes256_gcm_encrypt(
            session_key,
            &nonce,
            &aad,
            &mut self.bytes[Self::WIRE_PREFIX_LEN..],
        );

        let prefix = &mut self.bytes[..Self::WIRE_PREFIX_LEN];
        prefix[0] = QL_WIRE_VERSION;
        prefix[1] = RecordType::Session as u8;
        header.encode_into(&mut prefix[2..2 + SessionHeader::WIRE_SIZE]);
        prefix[2 + SessionHeader::WIRE_SIZE..].copy_from_slice(&auth);
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

    fn can_push_len(&self, len: usize) -> bool {
        len <= self.remaining_capacity()
    }

    fn ensure_prefix_capacity(&mut self, additional_body_len: usize) {
        if self.bytes.is_empty() {
            self.bytes
                .reserve(Self::WIRE_PREFIX_LEN + additional_body_len);
            self.bytes.resize(Self::WIRE_PREFIX_LEN, 0);
        }
    }
}
