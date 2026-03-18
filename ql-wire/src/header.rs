use zerocopy::{
    byte_slice::SplitByteSlice, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

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
        kind: kind as u8,
        sender: header.sender.0,
        recipient: header.recipient.0,
    }
}

pub(crate) fn decode_record_header<B: SplitByteSlice>(
    bytes: B,
) -> Result<(DecodedRecordHeader, B), WireError> {
    let (wire, payload_bytes) = codec::read_prefix::<QlRecordHeaderWire, B>(bytes)?;
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
