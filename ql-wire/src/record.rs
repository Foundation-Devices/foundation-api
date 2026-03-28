use crate::{
    codec,
    encrypted_message::EncryptedMessage,
    handshake::{self, Confirm, Hello, HelloReply, Ready},
    header::{decode_record_header, encode_record_header, QlHeader},
    pair::PairRequestRecord,
    unpair::Unpair,
    WireError, QL_WIRE_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QlRecord {
    pub header: QlHeader,
    pub payload: QlPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlPayload {
    PairRequest(PairRequestRecord<Vec<u8>>),
    Unpair(Unpair),
    Hello(Hello),
    HelloReply(HelloReply),
    Confirm(Confirm),
    Ready(Ready<Vec<u8>>),
    Session(EncryptedMessage<Vec<u8>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QlRecordRef<B> {
    pub header: QlHeader,
    pub payload: QlPayloadRef<B>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlPayloadRef<B> {
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
    fn for_payload(payload: &QlPayload) -> Self {
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

impl QlRecord {
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

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(Self::parse(bytes)?.to_owned())
    }

    pub fn parse(bytes: &[u8]) -> Result<QlRecordRef<&[u8]>, WireError> {
        QlRecordRef::parse(bytes)
    }

    pub fn parse_mut(bytes: &mut [u8]) -> Result<QlRecordRef<&mut [u8]>, WireError> {
        QlRecordRef::parse(bytes)
    }
}

impl<B: crate::ByteSlice> QlRecordRef<B> {
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
}

impl<B: AsRef<[u8]>> QlRecordRef<B> {
    pub fn to_owned(&self) -> QlRecord {
        QlRecord {
            header: self.header,
            payload: self.payload.to_owned(),
        }
    }
}

impl<B: AsRef<[u8]>> QlPayloadRef<B> {
    pub fn to_owned(&self) -> QlPayload {
        match self {
            Self::PairRequest(request) => QlPayload::PairRequest(PairRequestRecord {
                kem_ct: request.kem_ct.clone(),
                encrypted: EncryptedMessage {
                    nonce: request.encrypted.nonce,
                    auth: request.encrypted.auth,
                    ciphertext: request.encrypted.ciphertext.as_ref().to_vec(),
                },
            }),
            Self::Unpair(unpair) => QlPayload::Unpair(unpair.clone()),
            Self::Hello(hello) => QlPayload::Hello(hello.clone()),
            Self::HelloReply(reply) => QlPayload::HelloReply(reply.clone()),
            Self::Confirm(confirm) => QlPayload::Confirm(confirm.clone()),
            Self::Ready(ready) => QlPayload::Ready(Ready {
                encrypted: EncryptedMessage {
                    nonce: ready.encrypted.nonce,
                    auth: ready.encrypted.auth,
                    ciphertext: ready.encrypted.ciphertext.as_ref().to_vec(),
                },
            }),
            Self::Session(encrypted) => QlPayload::Session(EncryptedMessage {
                nonce: encrypted.nonce,
                auth: encrypted.auth,
                ciphertext: encrypted.ciphertext.as_ref().to_vec(),
            }),
        }
    }
}

fn parse_payload<B: crate::ByteSlice>(
    kind: RecordKind,
    payload: B,
) -> Result<QlPayloadRef<B>, WireError> {
    match kind {
        RecordKind::PairRequest => Ok(QlPayloadRef::PairRequest(PairRequestRecord::parse(
            payload,
        )?)),
        RecordKind::Unpair => Ok(QlPayloadRef::Unpair(Unpair::decode(&payload[..])?)),
        RecordKind::Hello => Ok(QlPayloadRef::Hello(handshake::Hello::decode(&payload[..])?)),
        RecordKind::HelloReply => Ok(QlPayloadRef::HelloReply(HelloReply::decode(&payload[..])?)),
        RecordKind::Confirm => Ok(QlPayloadRef::Confirm(Confirm::decode(&payload[..])?)),
        RecordKind::Ready => Ok(QlPayloadRef::Ready(Ready::parse(payload)?)),
        RecordKind::Session => Ok(QlPayloadRef::Session(EncryptedMessage::parse(payload)?)),
    }
}
