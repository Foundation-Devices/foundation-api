use crate::{
    codec,
    handshake::{Ik1, Ik2, Kk1, Kk2, Xx1, Xx2, Xx3, Xx4},
    ByteBuf, ByteSlice, SessionHeader, WireDecode, WireEncode, WireError,
    ENCRYPTED_MESSAGE_AUTH_SIZE, QL_WIRE_VERSION,
};

pub fn encode_record<B: ByteBuf, T: WireEncode + ?Sized>(
    record_type: RecordType,
    body: &T,
) -> B {
    let mut out = B::with_capacity(RecordHeader::WIRE_SIZE + body.encoded_len());
    RecordHeader {
        version: QL_WIRE_VERSION,
        record_type,
    }
    .encode(&mut out);
    body.encode(&mut out);
    out
}

pub fn decode_record<T, B>(bytes: B) -> Result<(RecordHeader, T), WireError>
where
    T: WireDecode<B>,
    B: ByteSlice,
{
    let mut reader = codec::Reader::new(bytes);
    Ok((reader.decode()?, reader.decode()?))
}

pub fn decode_session_record_prefix(
    bytes: &[u8],
) -> Result<(SessionHeader, [u8; ENCRYPTED_MESSAGE_AUTH_SIZE], usize), WireError> {
    let mut reader = codec::Reader::new(bytes);
    let record = reader.decode::<RecordHeader>()?;
    if record.version != QL_WIRE_VERSION || record.record_type != RecordType::Session {
        return Err(WireError::InvalidPayload);
    }

    let header = reader.decode::<SessionHeader>()?;
    let auth = reader.decode()?;
    let ciphertext_start = bytes.len().saturating_sub(reader.remaining_len());
    Ok((header, auth, ciphertext_start))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub version: u8,
    pub record_type: RecordType,
}

impl RecordHeader {
    pub const WIRE_SIZE: usize = size_of::<u8>() + size_of::<u8>();
}

impl<B: ByteSlice> WireDecode<B> for RecordHeader {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            version: reader.decode()?,
            record_type: reader.decode()?,
        })
    }
}

impl WireEncode for RecordHeader {
    fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u8(self.version);
        self.record_type.encode(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    Handshake = 1,
    Session = 2,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlHandshakeRecord {
    Ik1(Ik1),
    Ik2(Ik2),
    Kk1(Kk1),
    Kk2(Kk2),
    Xx1(Xx1),
    Xx2(Xx2),
    Xx3(Xx3),
    Xx4(Xx4),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeKind {
    Ik1 = 1,
    Ik2 = 2,
    Kk1 = 3,
    Kk2 = 4,
    Xx1 = 5,
    Xx2 = 6,
    Xx3 = 7,
    Xx4 = 8,
}

impl TryFrom<u8> for HandshakeKind {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ik1),
            2 => Ok(Self::Ik2),
            3 => Ok(Self::Kk1),
            4 => Ok(Self::Kk2),
            5 => Ok(Self::Xx1),
            6 => Ok(Self::Xx2),
            7 => Ok(Self::Xx3),
            8 => Ok(Self::Xx4),
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
            Self::Xx1(_) => HandshakeKind::Xx1,
            Self::Xx2(_) => HandshakeKind::Xx2,
            Self::Xx3(_) => HandshakeKind::Xx3,
            Self::Xx4(_) => HandshakeKind::Xx4,
        }
    }
}

impl WireEncode for QlHandshakeRecord {
    fn encoded_len(&self) -> usize {
        self.kind().encoded_len()
            + match self {
                Self::Ik1(message) => message.encoded_len(),
                Self::Ik2(message) => message.encoded_len(),
                Self::Kk1(message) => message.encoded_len(),
                Self::Kk2(message) => message.encoded_len(),
                Self::Xx1(message) => message.encoded_len(),
                Self::Xx2(message) => message.encoded_len(),
                Self::Xx3(message) => message.encoded_len(),
                Self::Xx4(message) => message.encoded_len(),
            }
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.kind().encode(out);
        match self {
            Self::Ik1(message) => message.encode(out),
            Self::Ik2(message) => message.encode(out),
            Self::Kk1(message) => message.encode(out),
            Self::Kk2(message) => message.encode(out),
            Self::Xx1(message) => message.encode(out),
            Self::Xx2(message) => message.encode(out),
            Self::Xx3(message) => message.encode(out),
            Self::Xx4(message) => message.encode(out),
        }
    }
}

impl<B: ByteSlice> WireDecode<B> for QlHandshakeRecord {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        let kind = reader.decode::<HandshakeKind>()?;
        match kind {
            HandshakeKind::Ik1 => Ok(Self::Ik1(reader.decode()?)),
            HandshakeKind::Ik2 => Ok(Self::Ik2(reader.decode()?)),
            HandshakeKind::Kk1 => Ok(Self::Kk1(reader.decode()?)),
            HandshakeKind::Kk2 => Ok(Self::Kk2(reader.decode()?)),
            HandshakeKind::Xx1 => Ok(Self::Xx1(reader.decode()?)),
            HandshakeKind::Xx2 => Ok(Self::Xx2(reader.decode()?)),
            HandshakeKind::Xx3 => Ok(Self::Xx3(reader.decode()?)),
            HandshakeKind::Xx4 => Ok(Self::Xx4(reader.decode()?)),
        }
    }
}
