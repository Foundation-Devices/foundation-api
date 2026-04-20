use super::{RecordAck, SessionClose, SessionFrame, StreamClose, StreamData, StreamWindow};
use crate::{
    BufView, ByteBuf, ConnectionId, Nonce, QlCrypto, RecordSeq, RecordType, SessionHeader,
    SessionKey, WireEncode, QL_WIRE_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecordBuilder<B: ByteBuf> {
    seq: RecordSeq,
    prefix_len: usize,
    max_capacity: usize,
    bytes: Option<B>,
}

impl<B: ByteBuf> SessionRecordBuilder<B> {
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
            bytes: None,
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
        self.bytes
            .as_ref()
            .map_or(0, |bytes| bytes.len().saturating_sub(self.prefix_len))
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn remaining_capacity(&self) -> usize {
        self.max_capacity
            .saturating_sub(self.prefix_len.saturating_add(self.len()))
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes
            .as_ref()
            .and_then(|bytes| bytes.get(self.prefix_len..))
            .unwrap_or_default()
    }

    pub fn push_ping(&mut self) -> bool {
        self.push_empty_frame(super::SessionFrameKind::Ping)
    }

    pub fn push_unpair(&mut self) -> bool {
        self.push_empty_frame(super::SessionFrameKind::Unpair)
    }

    pub fn push_ack(&mut self, ack: &RecordAck) -> bool {
        self.push_frame_payload(super::SessionFrameKind::Ack, ack)
    }

    pub fn push_stream_data<V: BufView>(&mut self, frame: &StreamData<V>) -> bool {
        self.push_frame_payload(super::SessionFrameKind::StreamData, frame)
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

    pub fn push_frame<V: BufView>(&mut self, frame: &SessionFrame<V>) -> bool {
        match frame {
            SessionFrame::Ping => self.push_ping(),
            SessionFrame::Unpair => self.push_unpair(),
            SessionFrame::Ack(frame) => self.push_ack(frame),
            SessionFrame::StreamData(frame) => self.push_stream_data(frame),
            SessionFrame::StreamWindow(frame) => self.push_stream_window(frame),
            SessionFrame::StreamClose(frame) => self.push_stream_close(frame),
            SessionFrame::Close(close) => self.push_close(close),
        }
    }

    pub fn encrypt<C: QlCrypto<B = B>>(
        self,
        crypto: &C,
        connection_id: ConnectionId,
        session_key: &SessionKey,
    ) -> B {
        let header = SessionHeader {
            connection_id,
            seq: self.seq,
        };
        let aad = header.aad();
        let nonce = Nonce::from_counter(self.seq.into_inner());
        let prefix_len = self.prefix_len;
        let bytes = self.into_bytes(0);
        let body_range = prefix_len..bytes.len();
        let (mut bytes, auth) =
            crypto.aes256_gcm_encrypt(session_key, &nonce, &aad, bytes, body_range);

        let mut prefix = &mut bytes[..prefix_len];
        prefix[0] = QL_WIRE_VERSION;
        prefix[1] = RecordType::Session as u8;
        prefix = &mut prefix[2..];
        header.encode(&mut prefix);
        auth.encode(&mut prefix);
        debug_assert!(prefix.is_empty());
        bytes
    }

    fn push_wire_size(&mut self, wire_size: usize, encode: impl FnOnce(&mut B)) -> bool {
        if !self.can_push_len(wire_size) {
            return false;
        }
        let bytes = self.bytes_mut(wire_size);
        let start = bytes.len();
        encode(bytes);
        debug_assert_eq!(bytes.len(), start + wire_size);
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

    fn can_push_len(&self, len: usize) -> bool {
        len <= self.remaining_capacity()
    }

    fn bytes_mut(&mut self, additional_body_len: usize) -> &mut B {
        self.ensure_bytes(additional_body_len);
        self.bytes.as_mut().unwrap()
    }

    fn into_bytes(mut self, additional_body_len: usize) -> B {
        self.ensure_bytes(additional_body_len);
        self.bytes.take().unwrap()
    }

    fn ensure_bytes(&mut self, additional_body_len: usize) {
        if self.bytes.is_none() {
            let mut bytes = B::with_capacity(self.prefix_len + additional_body_len);
            bytes.put_bytes(0, self.prefix_len);
            self.bytes = Some(bytes);
        }
    }
}
