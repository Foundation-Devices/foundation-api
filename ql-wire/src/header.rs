use zerocopy::{
    byte_slice::SplitByteSlice, FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes,
    Unaligned,
};

use crate::{codec, record::RecordKind, WireError, XID};

pub const QL_WIRE_VERSION: u8 = 1;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, TryFromBytes, KnownLayout, Immutable, IntoBytes, Unaligned,
)]
#[repr(u8)]
enum QlWireVersion {
    V1 = QL_WIRE_VERSION,
}

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

pub(crate) fn encode_record_header(header: &QlHeader, kind: RecordKind) -> QlRecordHeaderWire {
    QlRecordHeaderWire {
        version: QlWireVersion::V1 as u8,
        kind: kind as u8,
        sender: header.sender.0,
        recipient: header.recipient.0,
    }
}

pub(crate) fn decode_record_header<B: SplitByteSlice>(
    bytes: B,
) -> Result<(DecodedRecordHeader, B), WireError> {
    let (wire, payload_bytes) = codec::read_prefix::<QlRecordHeaderWire, B>(bytes)?;
    let QlWireVersion::V1 = codec::read_byte(wire.version)?;
    Ok((
        DecodedRecordHeader {
            kind: codec::read_byte(wire.kind)?,
            header: QlHeader {
                sender: XID(wire.sender),
                recipient: XID(wire.recipient),
            },
        },
        payload_bytes,
    ))
}
