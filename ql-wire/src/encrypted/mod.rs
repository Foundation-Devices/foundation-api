use crate::{
    codec, encrypted_message::EncryptedMessage, ByteChunks, ByteSlice, Nonce, QlCrypto,
    SessionHeader, SessionKey, VarInt, VarIntBoundsExceeded, WireDecode, WireEncode, WireError,
};

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

pub struct SessionFrameIter<'a> {
    remaining: &'a [u8],
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

impl SessionRecord {
    pub fn parse(bytes: &[u8]) -> Result<SessionFrameIter<'_>, WireError> {
        Ok(SessionFrameIter { remaining: bytes })
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

impl<'a> Iterator for SessionFrameIter<'a> {
    type Item = Result<SessionFrame<&'a [u8]>, WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }

        let parsed = parse_next_frame(self.remaining);
        match parsed {
            Ok((frame, rest)) => {
                self.remaining = rest;
                Some(Ok(frame))
            }
            Err(error) => {
                self.remaining = &[];
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

fn parse_next_frame(bytes: &[u8]) -> Result<(SessionFrame<&[u8]>, &[u8]), WireError> {
    let (&kind, rest) = bytes.split_first().ok_or(WireError::InvalidPayload)?;
    match SessionFrameKind::try_from(kind)? {
        SessionFrameKind::Ping => Ok((SessionFrame::Ping, rest)),
        SessionFrameKind::Ack => {
            let (frame, rest) = parse_inline_frame::<RecordAck>(rest)?;
            Ok((SessionFrame::Ack(frame), rest))
        }
        SessionFrameKind::StreamData => {
            let (frame, rest) = split_variable_frame(rest)?;
            Ok((
                SessionFrame::StreamData(StreamData::decode_exact(frame)?),
                rest,
            ))
        }
        SessionFrameKind::StreamWindow => {
            let (frame, rest) = parse_inline_frame::<StreamWindow>(rest)?;
            Ok((SessionFrame::StreamWindow(frame), rest))
        }
        SessionFrameKind::StreamClose => {
            let (frame, rest) = parse_inline_frame::<StreamClose>(rest)?;
            Ok((SessionFrame::StreamClose(frame), rest))
        }
        SessionFrameKind::Close => {
            let (frame, rest) = parse_inline_frame::<SessionClose>(rest)?;
            Ok((SessionFrame::Close(frame), rest))
        }
    }
}

fn parse_inline_frame<T>(bytes: &[u8]) -> Result<(T, &[u8]), WireError>
where
    T: for<'a> WireDecode<&'a [u8]>,
{
    let mut reader = codec::Reader::new(bytes);
    let frame = reader.decode::<T>()?;
    let consumed = bytes.len() - reader.remaining_len();
    Ok((frame, &bytes[consumed..]))
}

fn split_variable_frame(bytes: &[u8]) -> Result<(&[u8], &[u8]), WireError> {
    let mut reader = codec::Reader::new(bytes);
    let len = usize::try_from(reader.decode::<VarInt>()?.into_inner())
        .map_err(|_| WireError::InvalidPayload)?;
    let bytes = &bytes[bytes.len() - reader.remaining_len()..];
    bytes.split_at_checked(len).ok_or(WireError::InvalidPayload)
}
