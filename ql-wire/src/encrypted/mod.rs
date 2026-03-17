use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned};

use crate::{
    codec::{parse_mut, parse_ref, push_value, U64Le},
    encrypted_message::{EncryptedMessage, EncryptedMessageWire},
    Nonce, QlCrypto, QlHeader, QlPayload, QlRecord, SessionKey, SessionSeq, WireError,
};

pub mod close;
pub mod ping;
pub mod stream_chunk;
pub mod stream_close;
pub mod unpair;

pub use stream_chunk::{StreamChunk, StreamChunkMut, StreamChunkRef, StreamChunkWire};
pub use stream_close::{
    CloseCode, CloseTarget, StreamClose, StreamCloseMut, StreamCloseRef, StreamCloseWire,
};

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
    pub const EMPTY: Self = Self { base: 0, bitmap: 0 };
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

pub enum SessionBodyRef<'a> {
    Ack,
    Ping,
    Unpair,
    Stream(StreamChunkRef<'a>),
    StreamClose(StreamCloseRef<'a>),
    Close(close::SessionCloseBody),
}

pub enum SessionBodyMut<'a> {
    Ack,
    Ping,
    Unpair,
    Stream(StreamChunkMut<'a>),
    StreamClose(StreamCloseMut<'a>),
    Close(close::SessionCloseBody),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SessionBodyKind {
    Ack = 1,
    Ping = 2,
    Unpair = 3,
    Stream = 4,
    StreamClose = 5,
    Close = 6,
}

impl SessionBodyKind {
    fn from_byte(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::Ack),
            2 => Ok(Self::Ping),
            3 => Ok(Self::Unpair),
            4 => Ok(Self::Stream),
            5 => Ok(Self::StreamClose),
            6 => Ok(Self::Close),
            _ => Err(WireError::InvalidPayload),
        }
    }
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

pub type SessionEnvelopeRef<'a> = Ref<&'a [u8], SessionEnvelopeWire>;
pub type SessionEnvelopeMut<'a> = Ref<&'a mut [u8], SessionEnvelopeWire>;

impl SessionEnvelopeWire {
    pub fn parse(bytes: &[u8]) -> Result<SessionEnvelopeRef<'_>, WireError> {
        parse_ref(bytes)
    }

    pub fn parse_mut(bytes: &mut [u8]) -> Result<SessionEnvelopeMut<'_>, WireError> {
        parse_mut(bytes)
    }

    pub fn ack(&self) -> SessionAck {
        SessionAck {
            base: self.ack_base.get(),
            bitmap: self.ack_bitmap.get(),
        }
    }

    fn body_kind(&self) -> Result<SessionBodyKind, WireError> {
        SessionBodyKind::from_byte(self.kind)
    }

    pub fn body_ref(&self) -> Result<SessionBodyRef<'_>, WireError> {
        match self.body_kind()? {
            SessionBodyKind::Ack => {
                crate::codec::ensure_empty(&self.body)?;
                Ok(SessionBodyRef::Ack)
            }
            SessionBodyKind::Ping => {
                crate::codec::ensure_empty(&self.body)?;
                Ok(SessionBodyRef::Ping)
            }
            SessionBodyKind::Unpair => {
                crate::codec::ensure_empty(&self.body)?;
                Ok(SessionBodyRef::Unpair)
            }
            SessionBodyKind::Stream => {
                Ok(SessionBodyRef::Stream(StreamChunkWire::parse(&self.body)?))
            }
            SessionBodyKind::StreamClose => Ok(SessionBodyRef::StreamClose(
                StreamCloseWire::parse(&self.body)?,
            )),
            SessionBodyKind::Close => Ok(SessionBodyRef::Close(close::SessionCloseBody::decode(
                &self.body,
            )?)),
        }
    }

    pub fn body_mut(&mut self) -> Result<SessionBodyMut<'_>, WireError> {
        match self.body_kind()? {
            SessionBodyKind::Ack => {
                crate::codec::ensure_empty(&self.body)?;
                Ok(SessionBodyMut::Ack)
            }
            SessionBodyKind::Ping => {
                crate::codec::ensure_empty(&self.body)?;
                Ok(SessionBodyMut::Ping)
            }
            SessionBodyKind::Unpair => {
                crate::codec::ensure_empty(&self.body)?;
                Ok(SessionBodyMut::Unpair)
            }
            SessionBodyKind::Stream => Ok(SessionBodyMut::Stream(StreamChunkWire::parse_mut(
                &mut self.body,
            )?)),
            SessionBodyKind::StreamClose => Ok(SessionBodyMut::StreamClose(
                StreamCloseWire::parse_mut(&mut self.body)?,
            )),
            SessionBodyKind::Close => Ok(SessionBodyMut::Close(close::SessionCloseBody::decode(
                &self.body,
            )?)),
        }
    }

    pub fn to_session_envelope(&self) -> Result<SessionEnvelope, WireError> {
        let body = match self.body_ref()? {
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
            seq: self.seq.get(),
            ack: self.ack(),
            body,
        })
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
            seq: U64Le::new(self.seq),
            ack_base: U64Le::new(self.ack.base),
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

pub fn decrypt_record<'a>(
    crypto: &impl QlCrypto,
    header: &QlHeader,
    encrypted: &'a mut EncryptedMessageWire,
    session_key: &SessionKey,
) -> Result<SessionEnvelopeMut<'a>, WireError> {
    let aad = header.aad();
    let plaintext = encrypted.decrypt(crypto, session_key, &aad)?;
    SessionEnvelopeWire::parse_mut(plaintext)
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct SessionEnvelopeHeaderWire {
    seq: U64Le,
    ack_base: U64Le,
    ack_bitmap: U64Le,
    kind: u8,
}
