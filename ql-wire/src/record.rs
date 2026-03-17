use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    codec,
    encrypted_message::{EncryptedMessage, EncryptedMessageMut, EncryptedMessageRef},
    handshake,
    header::QlHeader,
    pair, WireError, XID, XID_SIZE,
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

pub struct QlRecordRef<'a> {
    pub header: QlHeader,
    pub payload: QlPayloadRef<'a>,
}

pub enum QlPayloadRef<'a> {
    PairRequest(pair::PairRequestRecordRef<'a>),
    Hello(handshake::Hello),
    HelloReply(handshake::HelloReply),
    Confirm(handshake::Confirm),
    Ready(handshake::ReadyRef<'a>),
    Session(EncryptedMessageRef<'a>),
}

pub struct QlRecordMut<'a> {
    pub header: QlHeader,
    pub payload: QlPayloadMut<'a>,
}

pub enum QlPayloadMut<'a> {
    PairRequest(pair::PairRequestRecordMut<'a>),
    Hello(handshake::Hello),
    HelloReply(handshake::HelloReply),
    Confirm(handshake::Confirm),
    Ready(handshake::ReadyMut<'a>),
    Session(EncryptedMessageMut<'a>),
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
}

impl RecordKind {
    pub(crate) fn from_byte(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::PairRequest),
            2 => Ok(Self::Hello),
            3 => Ok(Self::HelloReply),
            4 => Ok(Self::Confirm),
            5 => Ok(Self::Ready),
            6 => Ok(Self::Session),
            _ => Err(WireError::InvalidPayload),
        }
    }

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

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct QlRecordHeaderWire {
    version: u8,
    kind: u8,
    sender: [u8; XID_SIZE],
    recipient: [u8; XID_SIZE],
}

const QL_WIRE_VERSION: u8 = 1;

impl QlRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let header = QlRecordHeaderWire {
            version: QL_WIRE_VERSION,
            kind: RecordKind::for_payload(&self.payload) as u8,
            sender: self.header.sender.0,
            recipient: self.header.recipient.0,
        };
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

    pub fn parse(bytes: &[u8]) -> Result<QlRecordRef<'_>, WireError> {
        let (header, payload_bytes) = decode_record_header(bytes)?;
        let payload = parse_payload_ref(header.kind, payload_bytes)?;
        Ok(QlRecordRef {
            header: header.header,
            payload,
        })
    }

    pub fn parse_mut(bytes: &mut [u8]) -> Result<QlRecordMut<'_>, WireError> {
        let (header, payload_bytes) = decode_record_header_mut(bytes)?;
        let payload = parse_payload_mut(header.kind, payload_bytes)?;
        Ok(QlRecordMut {
            header: header.header,
            payload,
        })
    }
}

impl<'a> QlRecordRef<'a> {
    pub fn to_owned(&self) -> QlRecord {
        QlRecord {
            header: self.header,
            payload: self.payload.to_owned(),
        }
    }
}

impl<'a> QlPayloadRef<'a> {
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

impl<'a> QlRecordMut<'a> {
    pub fn to_owned(&self) -> QlRecord {
        QlRecord {
            header: self.header,
            payload: self.payload.to_owned(),
        }
    }
}

impl<'a> QlPayloadMut<'a> {
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

#[derive(Debug, Clone, Copy)]
struct DecodedRecordHeader {
    kind: RecordKind,
    header: QlHeader,
}

fn decode_record_header(bytes: &[u8]) -> Result<(DecodedRecordHeader, &[u8]), WireError> {
    let (wire, payload_bytes) = codec::read_prefix::<QlRecordHeaderWire>(bytes)?;
    if wire.version != QL_WIRE_VERSION {
        return Err(WireError::InvalidPayload);
    }
    Ok((
        DecodedRecordHeader {
            kind: RecordKind::from_byte(wire.kind)?,
            header: QlHeader {
                sender: XID(wire.sender),
                recipient: XID(wire.recipient),
            },
        },
        payload_bytes,
    ))
}

fn decode_record_header_mut(
    bytes: &mut [u8],
) -> Result<(DecodedRecordHeader, &mut [u8]), WireError> {
    let (wire, payload_bytes) = codec::read_prefix_mut::<QlRecordHeaderWire>(bytes)?;
    if wire.version != QL_WIRE_VERSION {
        return Err(WireError::InvalidPayload);
    }
    Ok((
        DecodedRecordHeader {
            kind: RecordKind::from_byte(wire.kind)?,
            header: QlHeader {
                sender: XID(wire.sender),
                recipient: XID(wire.recipient),
            },
        },
        payload_bytes,
    ))
}

fn parse_payload_ref<'a>(
    kind: RecordKind,
    payload: &'a [u8],
) -> Result<QlPayloadRef<'a>, WireError> {
    match kind {
        RecordKind::PairRequest => Ok(QlPayloadRef::PairRequest(
            pair::PairRequestRecordWire::parse(payload)?,
        )),
        RecordKind::Hello => Ok(QlPayloadRef::Hello(handshake::Hello::decode(payload)?)),
        RecordKind::HelloReply => Ok(QlPayloadRef::HelloReply(handshake::HelloReply::decode(
            payload,
        )?)),
        RecordKind::Confirm => Ok(QlPayloadRef::Confirm(handshake::Confirm::decode(payload)?)),
        RecordKind::Ready => Ok(QlPayloadRef::Ready(
            crate::encrypted_message::EncryptedMessageWire::parse(payload)?,
        )),
        RecordKind::Session => Ok(QlPayloadRef::Session(
            crate::encrypted_message::EncryptedMessageWire::parse(payload)?,
        )),
    }
}

fn parse_payload_mut<'a>(
    kind: RecordKind,
    payload: &'a mut [u8],
) -> Result<QlPayloadMut<'a>, WireError> {
    match kind {
        RecordKind::PairRequest => Ok(QlPayloadMut::PairRequest(
            pair::PairRequestRecordWire::parse_mut(payload)?,
        )),
        RecordKind::Hello => Ok(QlPayloadMut::Hello(handshake::Hello::decode(payload)?)),
        RecordKind::HelloReply => Ok(QlPayloadMut::HelloReply(handshake::HelloReply::decode(
            payload,
        )?)),
        RecordKind::Confirm => Ok(QlPayloadMut::Confirm(handshake::Confirm::decode(payload)?)),
        RecordKind::Ready => Ok(QlPayloadMut::Ready(
            crate::encrypted_message::EncryptedMessageWire::parse_mut(payload)?,
        )),
        RecordKind::Session => Ok(QlPayloadMut::Session(
            crate::encrypted_message::EncryptedMessageWire::parse_mut(payload)?,
        )),
    }
}
