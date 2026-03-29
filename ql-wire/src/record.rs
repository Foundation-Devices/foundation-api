use crate::{
    codec,
    encrypted_message::EncryptedMessage,
    handshake::{self, Confirm, Hello, HelloReply, Ready},
    header::{decode_record_header, encode_record_header, QlHeader},
    pair::PairRequestRecord,
    unpair::Unpair,
    ByteSlice, WireError, QL_WIRE_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QlRecord<B> {
    pub header: QlHeader,
    pub payload: QlPayload<B>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlPayload<B> {
    PairRequest(PairRequestRecord<B>),
    Unpair(Unpair),
    Hello(Hello),
    HelloReply(HelloReply),
    Confirm(Confirm),
    Ready(Ready<B>),
    Session(EncryptedMessage<B>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RecordKind {
    PairRequest = 1,
    Hello = 2,
    HelloReply = 3,
    Confirm = 4,
    Ready = 5,
    Session = 6,
    Unpair = 7,
}

impl TryFrom<u8> for RecordKind {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::PairRequest),
            2 => Ok(Self::Hello),
            3 => Ok(Self::HelloReply),
            4 => Ok(Self::Confirm),
            5 => Ok(Self::Ready),
            6 => Ok(Self::Session),
            7 => Ok(Self::Unpair),
            _ => Err(WireError::InvalidPayload),
        }
    }
}

impl RecordKind {
    fn for_payload<B>(payload: &QlPayload<B>) -> Self {
        match payload {
            QlPayload::PairRequest(_) => Self::PairRequest,
            QlPayload::Unpair(_) => Self::Unpair,
            QlPayload::Hello(_) => Self::Hello,
            QlPayload::HelloReply(_) => Self::HelloReply,
            QlPayload::Confirm(_) => Self::Confirm,
            QlPayload::Ready(_) => Self::Ready,
            QlPayload::Session(_) => Self::Session,
        }
    }
}

impl<B: AsRef<[u8]>> QlRecord<B> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        codec::push_u8(&mut out, QL_WIRE_VERSION);
        encode_record_header(
            &mut out,
            &self.header,
            RecordKind::for_payload(&self.payload),
        );
        match &self.payload {
            QlPayload::PairRequest(request) => request.encode_into(&mut out),
            QlPayload::Unpair(unpair) => unpair.encode_into(&mut out),
            QlPayload::Hello(hello) => hello.encode_into(&mut out),
            QlPayload::HelloReply(reply) => reply.encode_into(&mut out),
            QlPayload::Confirm(confirm) => confirm.encode_into(&mut out),
            QlPayload::Ready(ready) => ready.encode_into(&mut out),
            QlPayload::Session(encrypted) => encrypted.encode_into(&mut out),
        }
        out
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
        let (header, payload_bytes) = decode_record_header(reader.take_rest())?;
        let payload = parse_payload(header.kind, payload_bytes)?;
        Ok(Self {
            header: header.header,
            payload,
        })
    }

    pub fn into_owned(self) -> QlRecord<Vec<u8>> {
        QlRecord {
            header: self.header,
            payload: self.payload.into_owned(),
        }
    }
}

impl<B: ByteSlice> QlPayload<B> {
    pub fn into_owned(self) -> QlPayload<Vec<u8>> {
        match self {
            Self::PairRequest(request) => QlPayload::PairRequest(request.into_owned()),
            Self::Unpair(unpair) => QlPayload::Unpair(unpair),
            Self::Hello(hello) => QlPayload::Hello(hello),
            Self::HelloReply(reply) => QlPayload::HelloReply(reply),
            Self::Confirm(confirm) => QlPayload::Confirm(confirm),
            Self::Ready(ready) => QlPayload::Ready(ready.into_owned()),
            Self::Session(encrypted) => QlPayload::Session(encrypted.into_owned()),
        }
    }
}

fn parse_payload<B: ByteSlice>(kind: RecordKind, payload: B) -> Result<QlPayload<B>, WireError> {
    match kind {
        RecordKind::PairRequest => Ok(QlPayload::PairRequest(PairRequestRecord::parse(payload)?)),
        RecordKind::Unpair => Ok(QlPayload::Unpair(Unpair::decode(&payload[..])?)),
        RecordKind::Hello => Ok(QlPayload::Hello(handshake::Hello::decode(&payload[..])?)),
        RecordKind::HelloReply => Ok(QlPayload::HelloReply(HelloReply::decode(&payload[..])?)),
        RecordKind::Confirm => Ok(QlPayload::Confirm(Confirm::decode(&payload[..])?)),
        RecordKind::Ready => Ok(QlPayload::Ready(Ready::parse(payload)?)),
        RecordKind::Session => Ok(QlPayload::Session(EncryptedMessage::parse(payload)?)),
    }
}
