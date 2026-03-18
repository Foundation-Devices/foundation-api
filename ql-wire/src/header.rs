use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{codec, record::RecordKind, WireError, XID};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QlHeader {
    pub sender: XID,
    pub recipient: XID,
}

impl QlHeader {
    pub fn aad(&self) -> Vec<u8> {
        codec::header_aad(self)
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub(crate) struct QlRecordHeaderWire {
    pub(crate) version: u8,
    pub(crate) kind: u8,
    pub(crate) sender: [u8; XID::SIZE],
    pub(crate) recipient: [u8; XID::SIZE],
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DecodedRecordHeader {
    pub(crate) kind: RecordKind,
    pub(crate) header: QlHeader,
}

const QL_WIRE_VERSION: u8 = 1;

pub(crate) fn encode_record_header(header: &QlHeader, kind: RecordKind) -> QlRecordHeaderWire {
    QlRecordHeaderWire {
        version: QL_WIRE_VERSION,
        kind: kind as u8,
        sender: header.sender.0,
        recipient: header.recipient.0,
    }
}

pub(crate) fn decode_record_header(
    bytes: &[u8],
) -> Result<(DecodedRecordHeader, &[u8]), WireError> {
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

pub(crate) fn decode_record_header_mut(
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
