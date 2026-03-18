use zerocopy::{
    byte_slice::{ByteSlice, SplitByteSlice},
    Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned,
};

use crate::{
    codec,
    encrypted_message::{EncryptedMessage, EncryptedMessageRef, EncryptedMessageWire},
    handshake,
    header::{decode_record_header, encode_record_header, QlHeader},
    pair, WireError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QlRecord {
    pub header: QlHeader,
    pub payload: QlPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QlPayload {
    PairRequest(pair::PairRequestRecord),
    Hello(handshake::Hello),
    HelloReply(handshake::HelloReply),
    Confirm(handshake::Confirm),
    Ready(handshake::Ready),
    Session(EncryptedMessage),
}

pub struct QlRecordRef<B> {
    pub header: QlHeader,
    pub payload: QlPayloadRef<B>,
}

pub enum QlPayloadRef<B> {
    PairRequest(pair::PairRequestRecordRef<B>),
    Hello(handshake::Hello),
    HelloReply(handshake::HelloReply),
    Confirm(handshake::Confirm),
    Ready(handshake::ReadyRef<B>),
    Session(EncryptedMessageRef<B>),
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, TryFromBytes, KnownLayout, Immutable, IntoBytes, Unaligned,
)]
#[repr(u8)]
pub(crate) enum RecordKind {
    PairRequest = 1,
    Hello = 2,
    HelloReply = 3,
    Confirm = 4,
    Ready = 5,
    Session = 6,
}

impl RecordKind {
    fn for_payload(payload: &QlPayload) -> Self {
        match payload {
            QlPayload::PairRequest(_) => Self::PairRequest,
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
        let header = encode_record_header(&self.header, RecordKind::for_payload(&self.payload));
        codec::push_value(&mut out, &header);
        match &self.payload {
            QlPayload::PairRequest(request) => request.encode_into(&mut out),
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

impl<B: SplitByteSlice> QlRecordRef<B> {
    pub fn parse(bytes: B) -> Result<Self, WireError> {
        let (header, payload_bytes) = decode_record_header(bytes)?;
        let payload = parse_payload(header.kind, payload_bytes)?;
        Ok(Self {
            header: header.header,
            payload,
        })
    }
}

impl<B: ByteSlice> QlRecordRef<B> {
    pub fn to_owned(&self) -> QlRecord {
        QlRecord {
            header: self.header,
            payload: self.payload.to_owned(),
        }
    }
}

impl<B: ByteSlice> QlPayloadRef<B> {
    pub fn to_owned(&self) -> QlPayload {
        match self {
            Self::PairRequest(request) => QlPayload::PairRequest(request.to_pair_request_record()),
            Self::Hello(hello) => QlPayload::Hello(hello.clone()),
            Self::HelloReply(reply) => QlPayload::HelloReply(reply.clone()),
            Self::Confirm(confirm) => QlPayload::Confirm(confirm.clone()),
            Self::Ready(ready) => QlPayload::Ready(handshake::Ready {
                encrypted: ready.to_encrypted_message(),
            }),
            Self::Session(encrypted) => QlPayload::Session(encrypted.to_encrypted_message()),
        }
    }
}

fn parse_payload<B: ByteSlice>(kind: RecordKind, payload: B) -> Result<QlPayloadRef<B>, WireError> {
    match kind {
        RecordKind::PairRequest => Ok(QlPayloadRef::PairRequest(
            pair::PairRequestRecordWire::parse(payload)?,
        )),
        RecordKind::Hello => Ok(QlPayloadRef::Hello(handshake::Hello::decode(&payload)?)),
        RecordKind::HelloReply => Ok(QlPayloadRef::HelloReply(handshake::HelloReply::decode(
            &payload,
        )?)),
        RecordKind::Confirm => Ok(QlPayloadRef::Confirm(handshake::Confirm::decode(&payload)?)),
        RecordKind::Ready => Ok(QlPayloadRef::Ready(EncryptedMessageWire::parse(payload)?)),
        RecordKind::Session => Ok(QlPayloadRef::Session(EncryptedMessageWire::parse(payload)?)),
    }
}
