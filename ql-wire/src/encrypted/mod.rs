use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    codec::{push_value, read_prefix, U64Le},
    encrypted_message::{EncryptedMessage, EncryptedMessageMut},
    Nonce, QlCrypto, QlHeader, QlPayload, QlRecord, SessionKey, SessionSeq, WireError,
};

pub mod close;
pub mod ping;
pub mod stream;
pub mod unpair;

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
    Stream(stream::StreamFrame),
    StreamClose(stream::StreamCloseFrame),
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

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct SessionEnvelopeHeaderWire {
    seq: U64Le,
    ack_base: U64Le,
    ack_bitmap: U64Le,
    kind: u8,
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
        let (header, payload) = read_prefix::<SessionEnvelopeHeaderWire>(bytes)?;
        let body = match SessionBodyKind::from_byte(header.kind)? {
            SessionBodyKind::Ack => {
                crate::codec::ensure_empty(payload)?;
                SessionBody::Ack
            }
            SessionBodyKind::Ping => {
                crate::codec::ensure_empty(payload)?;
                SessionBody::Ping(ping::PingBody)
            }
            SessionBodyKind::Unpair => {
                crate::codec::ensure_empty(payload)?;
                SessionBody::Unpair(unpair::UnpairBody)
            }
            SessionBodyKind::Stream => SessionBody::Stream(stream::StreamFrame::decode(payload)?),
            SessionBodyKind::StreamClose => {
                SessionBody::StreamClose(stream::StreamCloseFrame::decode(payload)?)
            }
            SessionBodyKind::Close => SessionBody::Close(close::SessionCloseBody::decode(payload)?),
        };
        Ok(Self {
            seq: header.seq.get(),
            ack: SessionAck {
                base: header.ack_base.get(),
                bitmap: header.ack_bitmap.get(),
            },
            body,
        })
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

pub fn decrypt_record(
    crypto: &impl QlCrypto,
    header: &QlHeader,
    encrypted: &mut EncryptedMessageMut<'_>,
    session_key: &SessionKey,
) -> Result<SessionEnvelope, WireError> {
    let aad = header.aad();
    let plaintext = encrypted.decrypt(crypto, session_key, &aad)?;
    SessionEnvelope::decode(plaintext)
}
