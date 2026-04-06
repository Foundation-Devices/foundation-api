use crate::{
    codec,
    encrypted_message::EncryptedMessage,
    handshake::{Ik1, Ik2, Kk1, Kk2},
    ByteSlice, SessionHeader, WireEncode, WireError, WireDecode, QL_WIRE_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QlSessionRecord<B> {
    pub header: SessionHeader,
    pub payload: EncryptedMessage<B>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlHandshakeRecord {
    Ik1(Ik1),
    Ik2(Ik2),
    Kk1(Kk1),
    Kk2(Kk2),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    Handshake = 1,
    Session = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub version: u8,
    pub record_type: RecordType,
}

impl TryFrom<u8> for RecordType {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Handshake),
            2 => Ok(Self::Session),
            _ => Err(WireError::InvalidPayload),
        }
    }
}

impl<B: ByteSlice> WireDecode<B> for RecordType {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        reader.decode::<u8>()?.try_into()
    }
}

impl WireEncode for RecordType {
    fn encoded_len(&self) -> usize {
        size_of::<u8>()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u8(*self as u8);
    }
}

impl<B: ByteSlice> WireDecode<B> for RecordHeader {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        let version = reader.decode()?;
        let record_type = reader.decode()?;
        Ok(Self {
            version,
            record_type,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeKind {
    Ik1 = 1,
    Ik2 = 2,
    Kk1 = 3,
    Kk2 = 4,
}

impl TryFrom<u8> for HandshakeKind {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ik1),
            2 => Ok(Self::Ik2),
            3 => Ok(Self::Kk1),
            4 => Ok(Self::Kk2),
            _ => Err(WireError::InvalidPayload),
        }
    }
}

impl<B: ByteSlice> WireDecode<B> for HandshakeKind {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        reader.decode::<u8>()?.try_into()
    }
}

impl WireEncode for HandshakeKind {
    fn encoded_len(&self) -> usize {
        size_of::<u8>()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u8(*self as u8);
    }
}

impl QlHandshakeRecord {
    pub fn kind(&self) -> HandshakeKind {
        match self {
            Self::Ik1(_) => HandshakeKind::Ik1,
            Self::Ik2(_) => HandshakeKind::Ik2,
            Self::Kk1(_) => HandshakeKind::Kk1,
            Self::Kk2(_) => HandshakeKind::Kk2,
        }
    }
}

impl WireEncode for QlHandshakeRecord {
    fn encoded_len(&self) -> usize {
        RecordType::Handshake.encoded_len()
            + HandshakeKind::Ik1.encoded_len()
            + size_of::<u8>()
            + match self {
                Self::Ik1(message) => message.encoded_len(),
                Self::Ik2(message) => message.encoded_len(),
                Self::Kk1(message) => message.encoded_len(),
                Self::Kk2(message) => message.encoded_len(),
            }
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u8(QL_WIRE_VERSION);
        RecordType::Handshake.encode(out);
        self.kind().encode(out);
        match self {
            Self::Ik1(message) => message.encode(out),
            Self::Ik2(message) => message.encode(out),
            Self::Kk1(message) => message.encode(out),
            Self::Kk2(message) => message.encode(out),
        }
    }
}

impl<B: ByteSlice> WireDecode<B> for QlHandshakeRecord {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        let header = reader.decode::<RecordHeader>()?;
        if header.version != QL_WIRE_VERSION {
            return Err(WireError::InvalidPayload);
        }
        if header.record_type != RecordType::Handshake {
            return Err(WireError::InvalidPayload);
        }
        let kind = reader.decode::<HandshakeKind>()?;
        match kind {
            HandshakeKind::Ik1 => Ok(Self::Ik1(reader.decode()?)),
            HandshakeKind::Ik2 => Ok(Self::Ik2(reader.decode()?)),
            HandshakeKind::Kk1 => Ok(Self::Kk1(reader.decode()?)),
            HandshakeKind::Kk2 => Ok(Self::Kk2(reader.decode()?)),
        }
    }
}

impl<B: AsRef<[u8]>> WireEncode for QlSessionRecord<B> {
    fn encoded_len(&self) -> usize {
        size_of::<u8>()
            + RecordType::Session.encoded_len()
            + self.header.encoded_len()
            + self.payload.encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u8(QL_WIRE_VERSION);
        RecordType::Session.encode(out);
        self.header.encode(out);
        self.payload.encode(out);
    }
}

impl<B: ByteSlice> QlSessionRecord<B> {
    pub fn into_owned(self) -> QlSessionRecord<Vec<u8>> {
        QlSessionRecord {
            header: self.header,
            payload: self.payload.into_owned(),
        }
    }
}

impl<B: ByteSlice> WireDecode<B> for QlSessionRecord<B> {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        let header = reader.decode::<RecordHeader>()?;
        if header.version != QL_WIRE_VERSION {
            return Err(WireError::InvalidPayload);
        }
        if header.record_type != RecordType::Session {
            return Err(WireError::InvalidPayload);
        }
        Ok(Self {
            header: reader.decode()?,
            payload: reader.decode()?,
        })
    }
}
