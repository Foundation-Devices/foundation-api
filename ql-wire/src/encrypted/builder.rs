use super::{
    push_variable_len, RecordAck, SessionClose, SessionFrame, SessionFrameKind, StreamClose,
    StreamData, StreamWindow, SIZE_LEN,
};
use crate::{
    encrypted_message::EncryptedMessage, ByteChunks, Nonce, QlCrypto, QlSessionRecord,
    SessionHeader, SessionKey,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecordBuilder {
    max_capacity: usize,
    bytes: Vec<u8>,
}

impl SessionRecordBuilder {
    pub fn new(max_capacity: usize) -> Self {
        let bytes = Vec::with_capacity(max_capacity);
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
        self.bytes.is_empty()
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
        if !self.can_push_len(1) {
            return false;
        }
        self.bytes.push(SessionFrameKind::Ping as u8);
        true
    }

    pub fn push_ack(&mut self, ack: &RecordAck) -> bool {
        if !self.can_push_len(1 + SIZE_LEN + ack.encoded_len()) {
            return false;
        }
        self.bytes.push(SessionFrameKind::Ack as u8);
        push_variable_len(&mut self.bytes, ack.encoded_len());
        ack.encode_into(&mut self.bytes);
        true
    }

    pub fn push_stream_data<B: ByteChunks>(&mut self, frame: &StreamData<B>) -> bool {
        if !self.can_push_len(1 + SIZE_LEN + frame.encoded_len()) {
            return false;
        }
        self.bytes.push(SessionFrameKind::StreamData as u8);
        push_variable_len(&mut self.bytes, frame.encoded_len());
        frame.encode_into(&mut self.bytes);
        true
    }

    pub fn push_stream_window(&mut self, frame: &StreamWindow) -> bool {
        if !self.can_push_len(1 + StreamWindow::WIRE_SIZE) {
            return false;
        }
        self.bytes.push(SessionFrameKind::StreamWindow as u8);
        frame.encode_into(&mut self.bytes);
        true
    }

    pub fn push_stream_close(&mut self, frame: &StreamClose) -> bool {
        if !self.can_push_len(1 + SIZE_LEN + frame.encoded_len()) {
            return false;
        }
        self.bytes.push(SessionFrameKind::StreamClose as u8);
        push_variable_len(&mut self.bytes, frame.encoded_len());
        frame.encode_into(&mut self.bytes);
        true
    }

    pub fn push_close(&mut self, close: &SessionClose) -> bool {
        if !self.can_push_len(1 + SessionClose::WIRE_SIZE) {
            return false;
        }
        self.bytes.push(SessionFrameKind::Close as u8);
        close.encode_into(&mut self.bytes);
        true
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
        self,
        crypto: &impl QlCrypto,
        header: SessionHeader,
        session_key: &SessionKey,
    ) -> QlSessionRecord<Vec<u8>> {
        let aad = header.aad();
        let nonce = Nonce::from_counter(header.seq.0);
        let encrypted = EncryptedMessage::encrypt(crypto, session_key, self.bytes, &nonce, &aad);
        QlSessionRecord {
            header,
            payload: encrypted,
        }
    }
}
