use std::mem::size_of;

use zerocopy::{
    byte_slice::{ByteSlice, ByteSliceMut},
    FromBytes, Immutable, IntoBytes, KnownLayout, Ref, TryFromBytes, Unaligned,
};

use crate::{
    codec::{parse, read_byte},
    encrypted_message::{EncryptedMessage, EncryptedMessageWire},
    Nonce, QlCrypto, QlHeader, QlPayload, QlRecord, SessionKey, WireError,
};

mod ack;
mod close;
mod stream_close;
mod stream_data;
mod stream_window;

pub use ack::*;
pub use close::*;
pub use stream_close::*;
pub use stream_data::*;
pub use stream_window::*;

// todo: should use even/odd based on xid ordering
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct StreamId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RecordSeq(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub seq: RecordSeq,
    pub frames: Vec<SessionFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionFrame {
    Ping,
    Ack(RecordAck),
    StreamData(StreamData),
    StreamWindow(StreamWindow),
    StreamClose(StreamClose),
    Close(SessionCloseBody),
}

pub enum SessionFrameRef<'a> {
    Ping,
    Ack(Ref<&'a [u8], RecordAckQire>),
    StreamData(Ref<&'a [u8], StreamDataWire>),
    StreamWindow(Ref<&'a [u8], StreamWindowWire>),
    StreamClose(Ref<&'a [u8], StreamCloseWire>),
    Close(Ref<&'a [u8], SessionCloseBodyWire>),
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, TryFromBytes, KnownLayout, Immutable, IntoBytes, Unaligned,
)]
#[repr(u8)]
pub(crate) enum SessionFrameKind {
    Ping = 1,
    Ack = 2,
    StreamData = 3,
    StreamWindow = 4,
    StreamClose = 5,
    Close = 6,
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct SessionRecordWire {
    pub seq: crate::codec::U64Le,
    pub frames: [u8],
}

pub struct SessionFrameIter<'a> {
    remaining: &'a [u8],
}

impl SessionRecord {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, SessionRecordWire>, WireError> {
        parse(bytes)
    }

    pub fn from_wire(wire: &SessionRecordWire) -> Result<Self, WireError> {
        let frames = wire
            .frames()
            .map(|frame| frame?.to_owned())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            seq: wire.seq(),
            frames,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.seq.0.to_le_bytes());
        for frame in &self.frames {
            frame.encode_into(&mut out);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Self::from_wire(&Self::parse(bytes)?)
    }
}

impl SessionRecordWire {
    pub fn seq(&self) -> RecordSeq {
        RecordSeq(self.seq.get())
    }

    pub fn frames(&self) -> SessionFrameIter<'_> {
        SessionFrameIter {
            remaining: &self.frames,
        }
    }
}

impl SessionFrame {
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

impl SessionFrameRef<'_> {
    pub fn to_owned(&self) -> Result<SessionFrame, WireError> {
        Ok(match self {
            Self::Ping => SessionFrame::Ping,
            Self::Ack(frame) => SessionFrame::Ack(RecordAck::from_wire(frame)?),
            Self::StreamData(frame) => SessionFrame::StreamData(StreamData::from_wire(frame)?),
            Self::StreamWindow(frame) => SessionFrame::StreamWindow(StreamWindow::from_wire(frame)),
            Self::StreamClose(frame) => SessionFrame::StreamClose(StreamClose::from_wire(frame)?),
            Self::Close(frame) => SessionFrame::Close(SessionCloseBody::from_wire(frame)),
        })
    }
}

impl<'a> Iterator for SessionFrameIter<'a> {
    type Item = Result<SessionFrameRef<'a>, WireError>;

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
    header: QlHeader,
    session_key: &SessionKey,
    body: &SessionRecord,
    nonce: Nonce,
) -> QlRecord {
    let aad = header.aad();
    let body = body.encode();
    let encrypted = EncryptedMessage::encrypt(crypto, session_key, body, &aad, nonce);
    QlRecord {
        header,
        payload: QlPayload::Session(encrypted),
    }
}

pub fn decrypt_record<'a, B: ByteSliceMut>(
    crypto: &impl QlCrypto,
    header: &QlHeader,
    encrypted: &'a mut Ref<B, EncryptedMessageWire>,
    session_key: &SessionKey,
) -> Result<Ref<&'a mut [u8], SessionRecordWire>, WireError> {
    let aad = header.aad();
    let plaintext = EncryptedMessage::decrypt_in_place(encrypted, crypto, session_key, &aad)?;
    SessionRecord::parse(plaintext)
}

fn parse_next_frame(bytes: &[u8]) -> Result<(SessionFrameRef<'_>, &[u8]), WireError> {
    let (&kind, rest) = bytes.split_first().ok_or(WireError::InvalidPayload)?;
    let kind: SessionFrameKind = read_byte(kind)?;
    match kind {
        SessionFrameKind::Ping => Ok((SessionFrameRef::Ping, rest)),
        SessionFrameKind::Ack => {
            let (frame, rest) = split_variable_frame(rest)?;
            Ok((SessionFrameRef::Ack(RecordAck::parse(frame)?), rest))
        }
        SessionFrameKind::StreamData => {
            let (frame, rest) = split_variable_frame(rest)?;
            Ok((SessionFrameRef::StreamData(StreamData::parse(frame)?), rest))
        }
        SessionFrameKind::StreamWindow => {
            let wire_size = StreamWindow::WIRE_SIZE;
            if rest.len() < wire_size {
                return Err(WireError::InvalidPayload);
            }
            let (frame, rest) = rest.split_at(wire_size);
            Ok((
                SessionFrameRef::StreamWindow(StreamWindow::parse(frame)?),
                rest,
            ))
        }
        SessionFrameKind::StreamClose => {
            let (frame, rest) = split_variable_frame(rest)?;
            Ok((
                SessionFrameRef::StreamClose(StreamClose::parse(frame)?),
                rest,
            ))
        }
        SessionFrameKind::Close => {
            let wire_size = SessionCloseBody::WIRE_SIZE;
            if rest.len() < wire_size {
                return Err(WireError::InvalidPayload);
            }
            let (frame, rest) = rest.split_at(wire_size);
            let frame = SessionCloseBody::parse(frame)?;
            Ok((SessionFrameRef::Close(frame), rest))
        }
    }
}

fn push_variable_len(out: &mut Vec<u8>, len: usize) {
    let len = u16::try_from(len).expect("session frame exceeds u16");
    out.extend_from_slice(&len.to_le_bytes());
}

fn split_variable_frame(bytes: &[u8]) -> Result<(&[u8], &[u8]), WireError> {
    const LEN_SIZE: usize = size_of::<u16>();

    if bytes.len() < LEN_SIZE {
        return Err(WireError::InvalidPayload);
    }
    let len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    let bytes = &bytes[LEN_SIZE..];
    bytes.split_at_checked(len).ok_or(WireError::InvalidPayload)
}
