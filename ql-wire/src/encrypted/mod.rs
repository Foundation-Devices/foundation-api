use crate::{
    codec, encrypted_message::EncryptedMessage, ByteChunks, ByteSlice, Nonce, QlCrypto,
    SessionHeader, SessionKey, VarInt, VarIntBoundsExceeded, WireDecode, WireEncode, WireError,
};
use bytes::Bytes;

mod ack;
mod builder;
mod close;
mod stream_close;
mod stream_data;
mod stream_window;

pub use ack::*;
pub use builder::*;
pub use close::*;
pub use stream_close::*;
pub use stream_data::*;
pub use stream_window::*;

// todo: should use even/odd based on xid ordering
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct StreamId(pub VarInt);

impl StreamId {
    pub const MAX_ENCODED_LEN: usize = VarInt::MAX_SIZE;

    pub const fn from_u32(value: u32) -> Self {
        Self(VarInt::from_u32(value))
    }

    pub fn from_u64(value: u64) -> Result<Self, VarIntBoundsExceeded> {
        Ok(Self(VarInt::from_u64(value)?))
    }

    pub const fn into_inner(self) -> u64 {
        self.0.into_inner()
    }
}

impl WireEncode for StreamId {
    fn encoded_len(&self) -> usize {
        self.0.size()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for StreamId {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self(reader.decode()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub frames: Vec<SessionFrameVec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionFrame<B> {
    Ping,
    Ack(RecordAck),
    StreamData(StreamData<B>),
    StreamWindow(StreamWindow),
    StreamClose(StreamClose),
    Close(SessionClose),
}

pub type SessionFrameVec = SessionFrame<Vec<u8>>;
pub type StreamDataVec = StreamData<Vec<u8>>;
pub type SessionFrameBytes = SessionFrame<Bytes>;
pub type StreamDataBytes = StreamData<Bytes>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum SessionFrameKind {
    Ping = 1,
    Ack = 2,
    StreamData = 3,
    StreamWindow = 4,
    StreamClose = 5,
    Close = 6,
}

pub struct SessionFrameIter<B> {
    remaining: Option<B>,
}

impl TryFrom<u8> for SessionFrameKind {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ping),
            2 => Ok(Self::Ack),
            3 => Ok(Self::StreamData),
            4 => Ok(Self::StreamWindow),
            5 => Ok(Self::StreamClose),
            6 => Ok(Self::Close),
            _ => Err(WireError::InvalidPayload),
        }
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for SessionFrameKind {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        reader.decode::<u8>()?.try_into()
    }
}

impl SessionRecord {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<SessionFrameIter<B>, WireError> {
        Ok(SessionFrameIter {
            remaining: Some(bytes),
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let frames = Self::parse(bytes)?;
        let frames = frames
            .map(|frame| frame.map(SessionFrame::into_owned))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { frames })
    }
}

impl<B> SessionFrame<B> {
    fn kind(&self) -> SessionFrameKind {
        match self {
            Self::Ping => SessionFrameKind::Ping,
            Self::Ack(_) => SessionFrameKind::Ack,
            Self::StreamData(_) => SessionFrameKind::StreamData,
            Self::StreamWindow(_) => SessionFrameKind::StreamWindow,
            Self::StreamClose(_) => SessionFrameKind::StreamClose,
            Self::Close(_) => SessionFrameKind::Close,
        }
    }
}

impl<B: ByteSlice> SessionFrame<B> {
    pub fn into_owned(self) -> SessionFrameVec {
        match self {
            Self::Ping => SessionFrame::Ping,
            Self::Ack(frame) => SessionFrame::Ack(frame),
            Self::StreamData(frame) => SessionFrame::StreamData(frame.into_owned()),
            Self::StreamWindow(frame) => SessionFrame::StreamWindow(frame),
            Self::StreamClose(frame) => SessionFrame::StreamClose(frame),
            Self::Close(frame) => SessionFrame::Close(frame),
        }
    }
}

impl<B: ByteChunks> WireEncode for SessionFrame<B> {
    fn encoded_len(&self) -> usize {
        1 + match self {
            Self::Ping => 0,
            Self::Ack(frame) => frame.encoded_len(),
            Self::StreamData(frame) => {
                let payload_len = frame.encoded_len();
                VarInt::try_from(payload_len)
                    .unwrap_or(VarInt::MAX)
                    .encoded_len()
                    + payload_len
            }
            Self::StreamWindow(frame) => frame.encoded_len(),
            Self::StreamClose(frame) => frame.encoded_len(),
            Self::Close(frame) => frame.encoded_len(),
        }
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u8(self.kind() as u8);
        match self {
            Self::Ping => {}
            Self::Ack(frame) => frame.encode(out),
            Self::StreamData(frame) => {
                let payload_len = frame.encoded_len();
                let payload_len = VarInt::try_from(payload_len)
                    .expect("stream data frame length must fit ql-wire varint");
                payload_len.encode(out);
                frame.encode(out);
            }
            Self::StreamWindow(frame) => frame.encode(out),
            Self::StreamClose(frame) => frame.encode(out),
            Self::Close(frame) => frame.encode(out),
        }
    }
}

impl WireEncode for SessionRecord {
    fn encoded_len(&self) -> usize {
        self.frames
            .iter()
            .map(WireEncode::encoded_len)
            .sum::<usize>()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        for frame in &self.frames {
            frame.encode(out);
        }
    }
}

impl<B: ByteSlice> Iterator for SessionFrameIter<B> {
    type Item = Result<SessionFrame<B>, WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = self.remaining.take()?;
        if remaining.is_empty() {
            return None;
        }

        let parsed = parse_next_frame(remaining);
        match parsed {
            Ok((frame, rest)) => {
                self.remaining = Some(rest);
                Some(Ok(frame))
            }
            Err(error) => {
                Some(Err(error))
            }
        }
    }
}

pub fn decrypt_record<B: AsMut<[u8]>>(
    crypto: &impl QlCrypto,
    header: &SessionHeader,
    encrypted: EncryptedMessage<B>,
    session_key: &SessionKey,
) -> Result<B, WireError> {
    let aad = header.aad();
    let nonce = Nonce::from_counter(header.seq.into_inner());
    encrypted.decrypt_in_place(crypto, session_key, &nonce, &aad)
}

fn parse_next_frame<B: ByteSlice>(bytes: B) -> Result<(SessionFrame<B>, B), WireError> {
    let mut reader = codec::Reader::new(bytes);
    let kind = reader.decode::<SessionFrameKind>()?;
    let frame = match kind {
        SessionFrameKind::Ping => SessionFrame::Ping,
        SessionFrameKind::Ack => SessionFrame::Ack(reader.decode::<RecordAck>()?),
        SessionFrameKind::StreamData => {
            let len = usize::try_from(reader.decode::<VarInt>()?.into_inner())
                .map_err(|_| WireError::InvalidPayload)?;
            let frame = reader.take_bytes(len)?;
            SessionFrame::StreamData(StreamData::decode_exact(frame)?)
        }
        SessionFrameKind::StreamWindow => {
            SessionFrame::StreamWindow(reader.decode::<StreamWindow>()?)
        }
        SessionFrameKind::StreamClose => {
            SessionFrame::StreamClose(reader.decode::<StreamClose>()?)
        }
        SessionFrameKind::Close => SessionFrame::Close(reader.decode::<SessionClose>()?),
    };
    Ok((frame, reader.take_rest()))
}
