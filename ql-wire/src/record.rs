use crate::{
    codec,
    encrypted_message::EncryptedMessage,
    handshake::{Ik1, Ik2, Kk1, Kk2},
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

    fn encoded_len(&self) -> usize {
        match self {
            Self::Ik1(_) => Ik1::ENCODED_LEN,
            Self::Ik2(_) => Ik2::ENCODED_LEN,
            Self::Kk1(_) => Kk1::ENCODED_LEN,
            Self::Kk2(_) => Kk2::ENCODED_LEN,
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

    fn decode_payload(kind: HandshakeKind, bytes: &[u8]) -> Result<Self, WireError> {
        match kind {
            HandshakeKind::Ik1 => Ok(Self::Ik1(Ik1::decode(bytes)?)),
            HandshakeKind::Ik2 => Ok(Self::Ik2(Ik2::decode(bytes)?)),
            HandshakeKind::Kk1 => Ok(Self::Kk1(Kk1::decode(bytes)?)),
            HandshakeKind::Kk2 => Ok(Self::Kk2(Kk2::decode(bytes)?)),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0; 3 + self.encoded_len()];
        let rest = codec::write_u8(&mut out, QL_WIRE_VERSION);
        let rest = codec::write_u8(rest, RecordType::Handshake as u8);
        let rest = codec::write_u8(rest, self.kind() as u8);
        let _ = self.encode_into(rest);
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
        let mut out =
            vec![0; 2 + SessionHeader::ENCODED_LEN + EncryptedMessage::<&[u8]>::HEADER_LEN + self.payload.ciphertext.as_ref().len()];
        let rest = codec::write_u8(&mut out, QL_WIRE_VERSION);
        let rest = codec::write_u8(rest, RecordType::Session as u8);
        let rest = codec::write_bytes(rest, &self.header.encode());
        let _ = self.payload.encode_into(rest);
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
