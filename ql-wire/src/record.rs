use crate::{
    codec,
    encrypted_message::EncryptedMessage,
    handshake::{Ik1, Ik2, Kk1, Kk2},
    ByteSlice, SessionHeader, WireError, WireParse, QL_WIRE_VERSION,
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

impl<B: ByteSlice> WireParse<B> for RecordHeader {
    fn parse(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        let version = reader.take_u8()?;
        let record_type = RecordType::try_from(reader.take_u8()?)?;
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

impl QlHandshakeRecord {
    pub fn kind(&self) -> HandshakeKind {
        match self {
            Self::Ik1(_) => HandshakeKind::Ik1,
            Self::Ik2(_) => HandshakeKind::Ik2,
            Self::Kk1(_) => HandshakeKind::Kk1,
            Self::Kk2(_) => HandshakeKind::Kk2,
        }
    }

    fn wire_size(&self) -> usize {
        match self {
            Self::Ik1(_) => Ik1::WIRE_SIZE,
            Self::Ik2(_) => Ik2::WIRE_SIZE,
            Self::Kk1(_) => Kk1::WIRE_SIZE,
            Self::Kk2(_) => Kk2::WIRE_SIZE,
        }
    }

    fn encode_into<'a>(&self, out: &'a mut [u8]) -> &'a mut [u8] {
        match self {
            Self::Ik1(message) => message.encode_into(out),
            Self::Ik2(message) => message.encode_into(out),
            Self::Kk1(message) => message.encode_into(out),
            Self::Kk2(message) => message.encode_into(out),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0; 3 + self.wire_size()];
        let rest = codec::write_u8(&mut out, QL_WIRE_VERSION);
        let rest = codec::write_u8(rest, RecordType::Handshake as u8);
        let rest = codec::write_u8(rest, self.kind() as u8);
        let _ = self.encode_into(rest);
        out
    }
}

impl<B: ByteSlice> WireParse<B> for QlHandshakeRecord {
    fn parse(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        let header = reader.parse::<RecordHeader>()?;
        if header.version != QL_WIRE_VERSION {
            return Err(WireError::InvalidPayload);
        }
        if header.record_type != RecordType::Handshake {
            return Err(WireError::InvalidPayload);
        }
        let kind = HandshakeKind::try_from(reader.take_u8()?)?;
        match kind {
            HandshakeKind::Ik1 => Ok(Self::Ik1(reader.parse()?)),
            HandshakeKind::Ik2 => Ok(Self::Ik2(reader.parse()?)),
            HandshakeKind::Kk1 => Ok(Self::Kk1(reader.parse()?)),
            HandshakeKind::Kk2 => Ok(Self::Kk2(reader.parse()?)),
        }
    }
}

impl<B: AsRef<[u8]>> QlSessionRecord<B> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            0;
            2 + SessionHeader::WIRE_SIZE
                + EncryptedMessage::<&[u8]>::HEADER_LEN
                + self.payload.ciphertext.as_ref().len()
        ];
        let rest = codec::write_u8(&mut out, QL_WIRE_VERSION);
        let rest = codec::write_u8(rest, RecordType::Session as u8);
        let rest = codec::write_bytes(rest, &self.header.encode());
        let _ = self.payload.encode_into(rest);
        out
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

impl<B: ByteSlice> WireParse<B> for QlSessionRecord<B> {
    fn parse(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        let header = reader.parse::<RecordHeader>()?;
        if header.version != QL_WIRE_VERSION {
            return Err(WireError::InvalidPayload);
        }
        if header.record_type != RecordType::Session {
            return Err(WireError::InvalidPayload);
        }
        let header = reader.parse::<SessionHeader>()?;
        let payload = EncryptedMessage::parse(reader.take_bytes(reader.remaining_len())?)?;
        Ok(Self { header, payload })
    }
}
