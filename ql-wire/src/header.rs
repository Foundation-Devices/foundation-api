use crate::{codec, record::RecordKind, ByteSlice, WireError, XID};

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

#[derive(Debug, Clone, Copy)]
pub(crate) struct DecodedRecordHeader {
    pub(crate) kind: RecordKind,
    pub(crate) header: QlHeader,
}

pub(crate) fn encode_record_header(out: &mut Vec<u8>, header: &QlHeader, kind: RecordKind) {
    codec::push_u8(out, kind as u8);
    codec::push_bytes(out, &header.sender.0);
    codec::push_bytes(out, &header.recipient.0);
}

pub(crate) fn decode_record_header<B: ByteSlice>(
    bytes: B,
) -> Result<(DecodedRecordHeader, B), WireError> {
    let mut reader = codec::Reader::new(bytes);
    let kind = RecordKind::try_from(reader.take_u8()?)?;
    let sender = XID(reader.take_array()?);
    let recipient = XID(reader.take_array()?);
    Ok((
        DecodedRecordHeader {
            kind,
            header: QlHeader {
                sender,
                recipient,
            },
        },
        reader.take_rest(),
    ))
}
