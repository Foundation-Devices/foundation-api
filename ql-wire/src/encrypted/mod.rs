use crate::{
    codec, encrypted_message::EncryptedMessage, ByteChunks, ByteSlice, Nonce, QlCrypto,
    SessionHeader, SessionKey, WireError, WireParse,
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
pub struct StreamId(pub u32);

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

pub(crate) const SIZE_LEN: usize = size_of::<u16>();

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

    pub fn wire_size(&self) -> usize {
        self.frames
            .iter()
            .map(SessionFrame::wire_size)
            .sum::<usize>()
    }
}

impl<B: ByteChunks> SessionFrame<B> {
    pub fn wire_size(&self) -> usize {
        1 + match self {
            Self::Ping => 0,
            Self::Ack(_) => RecordAck::WIRE_SIZE,
            Self::StreamData(frame) => SIZE_LEN + frame.wire_size(),
            Self::StreamWindow(_) => StreamWindow::WIRE_SIZE,
            Self::StreamClose(_) => StreamClose::WIRE_SIZE,
            Self::Close(_) => SessionClose::WIRE_SIZE,
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
    let nonce = Nonce::from_counter(header.seq.0);
    encrypted.decrypt_in_place(crypto, session_key, &nonce, &aad)
}

fn parse_next_frame(bytes: &[u8]) -> Result<(SessionFrame<&[u8]>, &[u8]), WireError> {
    let (&kind, rest) = bytes.split_first().ok_or(WireError::InvalidPayload)?;
    match SessionFrameKind::try_from(kind)? {
        SessionFrameKind::Ping => Ok((SessionFrame::Ping, rest)),
        SessionFrameKind::Ack => {
            let (frame, rest) = rest
                .split_at_checked(RecordAck::WIRE_SIZE)
                .ok_or(WireError::InvalidPayload)?;
            Ok((SessionFrame::Ack(RecordAck::parse_bytes(frame)?), rest))
        }
        SessionFrameKind::StreamData => {
            let (frame, rest) = split_variable_frame(rest)?;
            Ok((SessionFrame::StreamData(StreamData::parse(frame)?), rest))
        }
        SessionFrameKind::StreamWindow => {
            let (frame, rest) = rest
                .split_at_checked(StreamWindow::WIRE_SIZE)
                .ok_or(WireError::InvalidPayload)?;
            Ok((
                SessionFrame::StreamWindow(StreamWindow::parse_bytes(frame)?),
                rest,
            ))
        }
        SessionFrameKind::StreamClose => {
            let (frame, rest) = rest
                .split_at_checked(StreamClose::WIRE_SIZE)
                .ok_or(WireError::InvalidPayload)?;
            Ok((
                SessionFrame::StreamClose(StreamClose::parse_bytes(frame)?),
                rest,
            ))
        }
        SessionFrameKind::Close => {
            let (frame, rest) = rest
                .split_at_checked(SessionClose::WIRE_SIZE)
                .ok_or(WireError::InvalidPayload)?;
            Ok((SessionFrame::Close(SessionClose::parse_bytes(frame)?), rest))
        }
    }
}

fn push_variable_len(out: &mut [u8], len: usize) {
    let len = u16::try_from(len).expect("session frame exceeds u16");
    let _ = codec::write_u16(out, len);
}

fn split_variable_frame(bytes: &[u8]) -> Result<(&[u8], &[u8]), WireError> {
    if bytes.len() < SIZE_LEN {
        return Err(WireError::InvalidPayload);
    }
    let len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    let bytes = &bytes[SIZE_LEN..];
    bytes.split_at_checked(len).ok_or(WireError::InvalidPayload)
}
