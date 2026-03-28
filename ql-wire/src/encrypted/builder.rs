use super::{
    push_variable_len, RecordAck, RecordSeq, SessionCloseBody, SessionFrame, SessionFrameKind,
    StreamClose, StreamData, StreamWindow,
};
use crate::{
    codec, encrypted_message::EncryptedMessage, Nonce, QlCrypto, QlHeader, QlPayload, QlRecord,
    SessionKey,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecordBuilder {
    max_capacity: usize,
    bytes: Vec<u8>,
}

impl SessionRecordBuilder {
    pub const HEADER_LEN: usize = std::mem::size_of::<u64>();
    pub const PING_ENCODED_LEN: usize = std::mem::size_of::<u8>();

    pub fn new(seq: RecordSeq, max_capacity: usize) -> Self {
        let max_capacity = max_capacity.max(Self::HEADER_LEN);
        let mut bytes = Vec::with_capacity(max_capacity);
        codec::push_u64(&mut bytes, seq.0);
        Self {
            max_capacity,
            bytes,
        }
    }

    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.len() == Self::HEADER_LEN
    }

    pub fn remaining_capacity(&self) -> usize {
        self.max_capacity.saturating_sub(self.bytes.len())
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_plaintext(self) -> Vec<u8> {
        self.bytes
    }

    pub fn can_push_len(&self, len: usize) -> bool {
        len <= self.remaining_capacity() || self.is_empty()
    }

    pub fn push_ping(&mut self) -> bool {
        if !self.can_push_len(Self::PING_ENCODED_LEN) {
            return false;
        }
        self.bytes.push(SessionFrameKind::Ping as u8);
        true
    }

    pub fn push_ack(&mut self, ack: &RecordAck) -> bool {
        if !self.can_push_len(ack.frame_encoded_len()) {
            return false;
        }
        self.bytes.push(SessionFrameKind::Ack as u8);
        push_variable_len(&mut self.bytes, ack.encoded_len());
        ack.encode_into(&mut self.bytes);
        true
    }

    pub fn push_stream_data<B: AsRef<[u8]>>(&mut self, frame: &StreamData<B>) -> bool {
        if !self.can_push_len(frame.frame_encoded_len()) {
            return false;
        }
        self.bytes.push(SessionFrameKind::StreamData as u8);
        push_variable_len(&mut self.bytes, frame.encoded_len());
        frame.encode_into(&mut self.bytes);
        true
    }

    pub fn push_stream_window(&mut self, frame: &StreamWindow) -> bool {
        if !self.can_push_len(StreamWindow::FRAME_ENCODED_LEN) {
            return false;
        }
        self.bytes.push(SessionFrameKind::StreamWindow as u8);
        frame.encode_into(&mut self.bytes);
        true
    }

    pub fn push_stream_close<B: AsRef<[u8]>>(&mut self, frame: &StreamClose<B>) -> bool {
        if !self.can_push_len(frame.frame_encoded_len()) {
            return false;
        }
        self.bytes.push(SessionFrameKind::StreamClose as u8);
        push_variable_len(&mut self.bytes, frame.encoded_len());
        frame.encode_into(&mut self.bytes);
        true
    }

    pub fn push_close(&mut self, close: &SessionCloseBody) -> bool {
        if !self.can_push_len(SessionCloseBody::FRAME_ENCODED_LEN) {
            return false;
        }
        self.bytes.push(SessionFrameKind::Close as u8);
        close.encode_into(&mut self.bytes);
        true
    }

    pub fn push_frame<B: AsRef<[u8]>>(&mut self, frame: &SessionFrame<B>) -> bool {
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
        self,
        crypto: &impl QlCrypto,
        header: QlHeader,
        session_key: &SessionKey,
        nonce: Nonce,
    ) -> QlRecord {
        let aad = header.aad();
        let encrypted = EncryptedMessage::encrypt(crypto, session_key, self.bytes, &aad, nonce);
        QlRecord {
            header,
            payload: QlPayload::Session(encrypted),
        }
    }
}
