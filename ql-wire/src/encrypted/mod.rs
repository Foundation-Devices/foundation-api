use zerocopy::{
    byte_slice::{ByteSlice, ByteSliceMut},
    FromBytes, Immutable, IntoBytes, KnownLayout, Ref, TryFromBytes, Unaligned,
};

use crate::{
    codec::{parse, push_value, U64Le},
    encrypted_message::{EncryptedMessage, EncryptedMessageRef},
    Nonce, QlCrypto, QlHeader, QlPayload, QlRecord, SessionKey, WireError,
};

pub mod close;
pub mod ping;
pub mod stream_chunk;
pub mod stream_close;
pub mod unpair;

pub use stream_chunk::{StreamChunk, StreamChunkRef, StreamChunkWire};
pub use stream_close::{CloseCode, CloseTarget, StreamClose, StreamCloseRef, StreamCloseWire};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SessionSeq(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct StreamId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEnvelope {
    pub seq: SessionSeq,
    pub ack: SessionAck,
    pub body: SessionBody,
}

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
pub enum SessionBody {
    Ack,
    Ping(ping::PingBody),
    Unpair(unpair::UnpairBody),
    Stream(StreamChunk),
    StreamClose(StreamClose),
    Close(close::SessionCloseBody),
}

pub enum SessionBodyRef<B> {
    Ack,
    Ping,
    Unpair,
    Stream(StreamChunkRef<B>),
    StreamClose(StreamCloseRef<B>),
    Close(close::SessionCloseBody),
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, TryFromBytes, KnownLayout, Immutable, IntoBytes, Unaligned,
)]
#[repr(u8)]
enum SessionBodyKind {
    Ack = 1,
    Ping = 2,
    Unpair = 3,
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

pub type SessionEnvelopeRef<B> = Ref<B, SessionEnvelopeWire>;

impl SessionEnvelopeWire {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<SessionEnvelopeRef<B>, WireError> {
        parse(bytes)
    }

    fn body_kind(&self) -> Result<SessionBodyKind, WireError> {
        crate::codec::read_byte(self.kind)
    }

    pub fn to_session_envelope(&self) -> Result<SessionEnvelope, WireError> {
        let body = match parse_session_body(self.body_kind()?, &self.body)? {
            SessionBodyRef::Ack => SessionBody::Ack,
            SessionBodyRef::Ping => SessionBody::Ping(ping::PingBody),
            SessionBodyRef::Unpair => SessionBody::Unpair(unpair::UnpairBody),
            SessionBodyRef::Stream(frame) => SessionBody::Stream(frame.to_stream_chunk()?),
            SessionBodyRef::StreamClose(frame) => {
                SessionBody::StreamClose(frame.to_stream_close()?)
            }
            SessionBodyRef::Close(body) => SessionBody::Close(body),
        };
        Ok(SessionEnvelope {
            seq: SessionSeq(self.seq.get()),
            ack: SessionAck {
                base: SessionSeq(self.ack_base.get()),
                bitmap: self.ack_bitmap.get(),
            },
            body,
        })
    }
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
        SessionBodyKind::Unpair => {
            crate::codec::ensure_empty(&body)?;
            Ok(SessionBodyRef::Unpair)
        }
        SessionBodyKind::Stream => Ok(SessionBodyRef::Stream(StreamChunkWire::parse(body)?)),
        SessionBodyKind::StreamClose => {
            Ok(SessionBodyRef::StreamClose(StreamCloseWire::parse(body)?))
        }
        SessionBodyKind::Close => Ok(SessionBodyRef::Close(close::SessionCloseBody::decode(
            &body,
        )?)),
    }
}

impl SessionEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let kind = match &self.body {
            SessionBody::Ack => SessionBodyKind::Ack,
            SessionBody::Ping(_) => SessionBodyKind::Ping,
            SessionBody::Unpair(_) => SessionBodyKind::Unpair,
            SessionBody::Stream(_) => SessionBodyKind::Stream,
            SessionBody::StreamClose(_) => SessionBodyKind::StreamClose,
            SessionBody::Close(_) => SessionBodyKind::Close,
        };
        let header = SessionEnvelopeHeaderWire {
            seq: U64Le::new(self.seq.0),
            ack_base: U64Le::new(self.ack.base.0),
            ack_bitmap: U64Le::new(self.ack.bitmap),
            kind: kind as u8,
        };
        push_value(&mut out, &header);
        match &self.body {
            SessionBody::Ack | SessionBody::Ping(_) | SessionBody::Unpair(_) => {}
            SessionBody::Stream(frame) => frame.encode_into(&mut out),
            SessionBody::StreamClose(frame) => frame.encode_into(&mut out),
            SessionBody::Close(body) => body.encode_into(&mut out),
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        SessionEnvelopeWire::parse(bytes)?.to_session_envelope()
    }
}

pub fn encrypt_record(
    crypto: &impl QlCrypto,
    header: QlHeader,
    session_key: &SessionKey,
    body: &SessionEnvelope,
    nonce: Nonce,
) -> Result<QlRecord, WireError> {
    let aad = header.aad();
    let body_bytes = body.encode();
    let encrypted = EncryptedMessage::encrypt(crypto, session_key, body_bytes, &aad, nonce)?;
    Ok(QlRecord {
        header,
        payload: QlPayload::Session(encrypted),
    })
}

pub fn decrypt_record<'a, B: ByteSliceMut>(
    crypto: &impl QlCrypto,
    header: &QlHeader,
    encrypted: &'a mut EncryptedMessageRef<B>,
    session_key: &SessionKey,
) -> Result<SessionEnvelopeRef<&'a mut [u8]>, WireError> {
    let aad = header.aad();
    let plaintext = encrypted.decrypt(crypto, session_key, &aad)?;
    SessionEnvelopeWire::parse(plaintext)
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct SessionEnvelopeHeaderWire {
    seq: U64Le,
    ack_base: U64Le,
    ack_bitmap: U64Le,
    kind: u8,
}
