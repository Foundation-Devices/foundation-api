use crate::{
    codec,
    encrypted_message::EncryptedMessage,
    handshake::{Kk1, Kk2, Xx1, Xx2, Xx3, Xx4},
    ByteSlice, SessionHeader, WireError, QL_WIRE_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QlSessionRecord<B> {
    pub header: SessionHeader,
    pub payload: EncryptedMessage<B>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlRecord<B> {
    Handshake(QlHandshakeRecord),
    Session(QlSessionRecord<B>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlHandshakeRecord {
    Xx1(Xx1),
    Xx2(Xx2),
    Xx3(Xx3),
    Xx4(Xx4),
    Kk1(Kk1),
    Kk2(Kk2),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeKind {
    Xx1 = 1,
    Xx2 = 2,
    Xx3 = 3,
    Xx4 = 4,
    Kk1 = 5,
    Kk2 = 6,
}

impl TryFrom<u8> for HandshakeKind {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Xx1),
            2 => Ok(Self::Xx2),
            3 => Ok(Self::Xx3),
            4 => Ok(Self::Xx4),
            5 => Ok(Self::Kk1),
            6 => Ok(Self::Kk2),
            _ => Err(WireError::InvalidPayload),
        }
    }
}

impl QlHandshakeRecord {
    pub fn kind(&self) -> HandshakeKind {
        match self {
            Self::Xx1(_) => HandshakeKind::Xx1,
            Self::Xx2(_) => HandshakeKind::Xx2,
            Self::Xx3(_) => HandshakeKind::Xx3,
            Self::Xx4(_) => HandshakeKind::Xx4,
            Self::Kk1(_) => HandshakeKind::Kk1,
            Self::Kk2(_) => HandshakeKind::Kk2,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Xx1(message) => message.encode_into(out),
            Self::Xx2(message) => message.encode_into(out),
            Self::Xx3(message) => message.encode_into(out),
            Self::Xx4(message) => message.encode_into(out),
            Self::Kk1(message) => message.encode_into(out),
            Self::Kk2(message) => message.encode_into(out),
        }
    }

    fn decode_payload(kind: HandshakeKind, bytes: &[u8]) -> Result<Self, WireError> {
        match kind {
            HandshakeKind::Xx1 => Ok(Self::Xx1(Xx1::decode(bytes)?)),
            HandshakeKind::Xx2 => Ok(Self::Xx2(Xx2::decode(bytes)?)),
            HandshakeKind::Xx3 => Ok(Self::Xx3(Xx3::decode(bytes)?)),
            HandshakeKind::Xx4 => Ok(Self::Xx4(Xx4::decode(bytes)?)),
            HandshakeKind::Kk1 => Ok(Self::Kk1(Kk1::decode(bytes)?)),
            HandshakeKind::Kk2 => Ok(Self::Kk2(Kk2::decode(bytes)?)),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        codec::push_u8(&mut out, QL_WIRE_VERSION);
        codec::push_u8(&mut out, RecordType::Handshake as u8);
        codec::push_u8(&mut out, self.kind() as u8);
        self.encode_into(&mut out);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(Self::parse(bytes)?)
    }

    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        if reader.take_u8()? != QL_WIRE_VERSION {
            return Err(WireError::InvalidPayload);
        }
        if RecordType::try_from(reader.take_u8()?)? != RecordType::Handshake {
            return Err(WireError::InvalidPayload);
        }
        parse_handshake_record(reader.take_rest())
    }
}

impl<B: AsRef<[u8]>> QlSessionRecord<B> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        codec::push_u8(&mut out, QL_WIRE_VERSION);
        codec::push_u8(&mut out, RecordType::Session as u8);
        self.header.encode_into(&mut out);
        self.payload.encode_into(&mut out);
        out
    }
}

impl QlSessionRecord<Vec<u8>> {
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(QlSessionRecord::parse(bytes)?.into_owned())
    }
}

impl<B: ByteSlice> QlSessionRecord<B> {
    pub fn parse(bytes: B) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        if reader.take_u8()? != QL_WIRE_VERSION {
            return Err(WireError::InvalidPayload);
        }
        if RecordType::try_from(reader.take_u8()?)? != RecordType::Session {
            return Err(WireError::InvalidPayload);
        }
        parse_session_record(reader.take_rest())
    }

    pub fn into_owned(self) -> QlSessionRecord<Vec<u8>> {
        QlSessionRecord {
            header: self.header,
            payload: self.payload.into_owned(),
        }
    }
}

impl<B: AsRef<[u8]>> QlRecord<B> {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Handshake(record) => record.encode(),
            Self::Session(record) => record.encode(),
        }
    }
}

impl QlRecord<Vec<u8>> {
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(QlRecord::parse(bytes)?.into_owned())
    }
}

impl<B: ByteSlice> QlRecord<B> {
    pub fn parse(bytes: B) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        if reader.take_u8()? != QL_WIRE_VERSION {
            return Err(WireError::InvalidPayload);
        }

        let record_type = RecordType::try_from(reader.take_u8()?)?;
        let remaining = reader.take_rest();
        match record_type {
            RecordType::Handshake => Ok(Self::Handshake(parse_handshake_record(remaining)?)),
            RecordType::Session => Ok(Self::Session(parse_session_record(remaining)?)),
        }
    }

    pub fn into_owned(self) -> QlRecord<Vec<u8>> {
        match self {
            Self::Handshake(record) => QlRecord::Handshake(record),
            Self::Session(record) => QlRecord::Session(record.into_owned()),
        }
    }
}

fn parse_handshake_record<B: ByteSlice>(bytes: B) -> Result<QlHandshakeRecord, WireError> {
    let mut reader = codec::Reader::new(bytes);
    let kind = HandshakeKind::try_from(reader.take_u8()?)?;
    let payload = reader.take_rest();
    QlHandshakeRecord::decode_payload(kind, &payload[..])
}

fn parse_session_record<B: ByteSlice>(bytes: B) -> Result<QlSessionRecord<B>, WireError> {
    let mut reader = codec::Reader::new(bytes);
    let header = SessionHeader::decode_from(&mut reader)?;
    let payload = EncryptedMessage::parse(reader.take_rest())?;
    Ok(QlSessionRecord { header, payload })
}
