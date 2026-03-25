use std::mem::size_of;

use zerocopy::{
    byte_slice::{ByteSlice, ByteSliceMut},
    FromBytes, Immutable, IntoBytes, KnownLayout, Ref, TryFromBytes, Unaligned,
};

use crate::{
    codec::{parse, push_value, U64Le},
    encrypted_message::{EncryptedMessage, EncryptedMessageWire},
    Nonce, QlCrypto, QlHeader, QlPayload, QlRecord, SessionKey, WireError,
};

mod close;
mod ping;
mod stream_chunk;
mod stream_close;

pub use close::*;
pub use ping::*;
pub use stream_chunk::*;
pub use stream_close::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SessionSeq(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct StreamId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionAck {
    pub base: SessionSeq,
    pub bitmap: u64,
}

impl SessionAck {
    pub const EMPTY: Self = Self {
        base: SessionSeq(0),
        bitmap: 0,
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEnvelope {
    pub seq: SessionSeq,
    pub ack: SessionAck,
    pub body: SessionBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionBody {
    Ack,
    Ping(ping::PingBody),
    Stream(StreamChunk),
    StreamClose(StreamClose),
    Close(close::SessionCloseBody),
}

pub enum SessionBodyRef<B> {
    Ack,
    Ping,
    Stream(Ref<B, StreamChunkWire>),
    StreamClose(Ref<B, StreamCloseWire>),
    Close(close::SessionCloseBody),
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, TryFromBytes, KnownLayout, Immutable, IntoBytes, Unaligned,
)]
#[repr(u8)]
enum SessionBodyKind {
    Ack = 1,
    Ping = 2,
    Stream = 4,
    StreamClose = 5,
    Close = 6,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct SessionEnvelopeWire {
    pub seq: U64Le,
    pub ack_base: U64Le,
    pub ack_bitmap: U64Le,
    pub kind: u8,
    pub body: [u8],
}

impl SessionEnvelope {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, SessionEnvelopeWire>, WireError> {
        parse(bytes)
    }

    pub fn from_wire(wire: &SessionEnvelopeWire) -> Result<Self, WireError> {
        let body = match parse_session_body(session_body_kind(wire)?, &wire.body)? {
            SessionBodyRef::Ack => SessionBody::Ack,
            SessionBodyRef::Ping => SessionBody::Ping(ping::PingBody),
            SessionBodyRef::Stream(frame) => SessionBody::Stream(StreamChunk::from_wire(&frame)?),
            SessionBodyRef::StreamClose(frame) => {
                SessionBody::StreamClose(StreamClose::from_wire(&frame)?)
            }
            SessionBodyRef::Close(body) => SessionBody::Close(body),
        };
        Ok(Self {
            seq: SessionSeq(wire.seq.get()),
            ack: SessionAck {
                base: SessionSeq(wire.ack_base.get()),
                bitmap: wire.ack_bitmap.get(),
            },
            body,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_session_envelope(self.seq, self.ack, &self.body)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Self::from_wire(&Self::parse(bytes)?)
    }
}

pub fn encrypt_record(
    crypto: &impl QlCrypto,
    header: QlHeader,
    session_key: &SessionKey,
    body: &SessionEnvelope,
    nonce: Nonce,
) -> QlRecord {
    encrypt_record_parts(
        crypto,
        header,
        session_key,
        body.seq,
        body.ack,
        &body.body,
        nonce,
    )
}

pub fn encrypt_record_parts(
    crypto: &impl QlCrypto,
    header: QlHeader,
    session_key: &SessionKey,
    seq: SessionSeq,
    ack: SessionAck,
    body: &SessionBody,
    nonce: Nonce,
) -> QlRecord {
    let aad = header.aad();
    let body = encode_session_envelope(seq, ack, body);
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
) -> Result<Ref<&'a mut [u8], SessionEnvelopeWire>, WireError> {
    let aad = header.aad();
    let plaintext = EncryptedMessage::decrypt_in_place(encrypted, crypto, session_key, &aad)?;
    SessionEnvelope::parse(plaintext)
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct SessionEnvelopeHeaderWire {
    pub seq: U64Le,
    pub ack_base: U64Le,
    pub ack_bitmap: U64Le,
    pub kind: u8,
}

fn encode_session_envelope(seq: SessionSeq, ack: SessionAck, body: &SessionBody) -> Vec<u8> {
    let expected_len = size_of::<SessionEnvelopeHeaderWire>() + session_body_encoded_len(body);
    let mut out = Vec::with_capacity(expected_len);
    let initial_capacity = out.capacity();
    encode_session_envelope_into(seq, ack, body, &mut out);
    debug_assert_eq!(out.len(), expected_len);
    debug_assert_eq!(out.capacity(), initial_capacity);
    out
}

fn encode_session_envelope_into(
    seq: SessionSeq,
    ack: SessionAck,
    body: &SessionBody,
    out: &mut Vec<u8>,
) {
    let header = SessionEnvelopeHeaderWire {
        seq: U64Le::new(seq.0),
        ack_base: U64Le::new(ack.base.0),
        ack_bitmap: U64Le::new(ack.bitmap),
        kind: session_body_kind_for(body) as u8,
    };
    push_value(out, &header);
    encode_session_body_into(body, out);
}

fn session_body_kind_for(body: &SessionBody) -> SessionBodyKind {
    match body {
        SessionBody::Ack => SessionBodyKind::Ack,
        SessionBody::Ping(_) => SessionBodyKind::Ping,
        SessionBody::Stream(_) => SessionBodyKind::Stream,
        SessionBody::StreamClose(_) => SessionBodyKind::StreamClose,
        SessionBody::Close(_) => SessionBodyKind::Close,
    }
}

fn session_body_encoded_len(body: &SessionBody) -> usize {
    match body {
        SessionBody::Ack | SessionBody::Ping(_) => 0,
        SessionBody::Stream(frame) => size_of::<StreamChunkHeaderWire>() + frame.bytes.len(),
        SessionBody::StreamClose(frame) => size_of::<StreamCloseHeaderWire>() + frame.payload.len(),
        SessionBody::Close(_) => size_of::<SessionCloseBodyWire>(),
    }
}

fn encode_session_body_into(body: &SessionBody, out: &mut Vec<u8>) {
    match body {
        SessionBody::Ack | SessionBody::Ping(_) => {}
        SessionBody::Stream(frame) => frame.encode_into(out),
        SessionBody::StreamClose(frame) => frame.encode_into(out),
        SessionBody::Close(body) => body.encode_into(out),
    }
}

fn session_body_kind(wire: &SessionEnvelopeWire) -> Result<SessionBodyKind, WireError> {
    crate::codec::read_byte(wire.kind)
}

fn parse_session_body<B: ByteSlice>(
    kind: SessionBodyKind,
    body: B,
) -> Result<SessionBodyRef<B>, WireError> {
    match kind {
        SessionBodyKind::Ack => {
            crate::codec::ensure_empty(&body)?;
            Ok(SessionBodyRef::Ack)
        }
        SessionBodyKind::Ping => {
            crate::codec::ensure_empty(&body)?;
            Ok(SessionBodyRef::Ping)
        }
        SessionBodyKind::Stream => Ok(SessionBodyRef::Stream(StreamChunk::parse(body)?)),
        SessionBodyKind::StreamClose => Ok(SessionBodyRef::StreamClose(StreamClose::parse(body)?)),
        SessionBodyKind::Close => Ok(SessionBodyRef::Close(close::SessionCloseBody::decode(
            &body,
        )?)),
    }
}
