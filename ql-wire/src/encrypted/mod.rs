use std::mem::size_of;

use crate::{
    codec, encrypted_message::EncryptedMessage, ByteChunks, ByteSlice, Nonce, QlCrypto,
    QlSessionRecord, SessionHeader, SessionKey, WireError,
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
    Close(SessionCloseBody),
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
        let reader = codec::Reader::new(bytes);
        Ok(SessionFrameIter {
            remaining: reader.take_rest(),
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let frames = Self::parse(bytes)?;
        let frames = frames
            .map(|frame| frame.map(SessionFrame::into_owned))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { frames })
    }

    pub fn encoded_len(&self) -> usize {
        self.frames
            .iter()
            .map(SessionFrame::encoded_len)
            .sum::<usize>()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = SessionRecordBuilder::new(self.encoded_len());
        for frame in &self.frames {
            let pushed = out.push_frame(frame);
            debug_assert!(pushed);
        }
        out.into_plaintext()
    }
}

impl<B: ByteChunks> SessionFrame<B> {
    pub fn encoded_len(&self) -> usize {
        1 + match self {
            Self::Ping => 0,
            Self::Ack(frame) => SIZE_LEN + frame.encoded_len(),
            Self::StreamData(frame) => SIZE_LEN + frame.encoded_len(),
            Self::StreamWindow(_) => StreamWindow::WIRE_SIZE,
            Self::StreamClose(frame) => SIZE_LEN + frame.encoded_len(),
            Self::Close(_) => SessionCloseBody::WIRE_SIZE,
        }
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Ping => out.push(SessionFrameKind::Ping as u8),
            Self::Ack(frame) => {
                out.push(SessionFrameKind::Ack as u8);
                push_variable_len(out, frame.encoded_len());
                frame.encode_into(out);
            }
            Self::StreamData(frame) => {
                out.push(SessionFrameKind::StreamData as u8);
                push_variable_len(out, frame.encoded_len());
                frame.encode_into(out);
            }
            Self::StreamWindow(frame) => {
                out.push(SessionFrameKind::StreamWindow as u8);
                frame.encode_into(out);
            }
            Self::StreamClose(frame) => {
                out.push(SessionFrameKind::StreamClose as u8);
                push_variable_len(out, frame.encoded_len());
                frame.encode_into(out);
            }
            Self::Close(body) => {
                out.push(SessionFrameKind::Close as u8);
                body.encode_into(out);
            }
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

pub fn encrypt_record(
    crypto: &impl QlCrypto,
    header: SessionHeader,
    session_key: &SessionKey,
    body: &SessionRecord,
) -> QlSessionRecord<Vec<u8>> {
    let mut builder = SessionRecordBuilder::new(body.encoded_len());
    for frame in &body.frames {
        let pushed = builder.push_frame(frame);
        debug_assert!(pushed);
    }
    builder.encrypt(crypto, header, session_key)
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
            let (frame, rest) = split_variable_frame(rest)?;
            Ok((SessionFrame::Ack(RecordAck::decode(frame)?), rest))
        }
        SessionFrameKind::StreamData => {
            let (frame, rest) = split_variable_frame(rest)?;
            Ok((SessionFrame::StreamData(StreamData::parse(frame)?), rest))
        }
        SessionFrameKind::StreamWindow => {
            if rest.len() < StreamWindow::WIRE_SIZE {
                return Err(WireError::InvalidPayload);
            }
            let (frame, rest) = rest.split_at(StreamWindow::WIRE_SIZE);
            Ok((
                SessionFrame::StreamWindow(StreamWindow::decode(frame)?),
                rest,
            ))
        }
        SessionFrameKind::StreamClose => {
            let (frame, rest) = split_variable_frame(rest)?;
            Ok((SessionFrame::StreamClose(StreamClose::parse(frame)?), rest))
        }
        SessionFrameKind::Close => {
            if rest.len() < SessionCloseBody::WIRE_SIZE {
                return Err(WireError::InvalidPayload);
            }
            let (frame, rest) = rest.split_at(SessionCloseBody::WIRE_SIZE);
            Ok((SessionFrame::Close(SessionCloseBody::decode(frame)?), rest))
        }
    }
}

fn push_variable_len(out: &mut Vec<u8>, len: usize) {
    let len = u16::try_from(len).expect("session frame exceeds u16");
    codec::push_u16(out, len);
}

fn split_variable_frame(bytes: &[u8]) -> Result<(&[u8], &[u8]), WireError> {
    if bytes.len() < SIZE_LEN {
        return Err(WireError::InvalidPayload);
    }
    let len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    let bytes = &bytes[SIZE_LEN..];
    bytes.split_at_checked(len).ok_or(WireError::InvalidPayload)
}
