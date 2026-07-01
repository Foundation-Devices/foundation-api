use ql_common::{StreamId, VarInt};

use crate::{
    codec::{self, LenBytes},
    BufView, ByteSlice, WireDecode, WireEncode, WireError,
};

/// carries bytes for a stream and may finish that sending direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamData<B, H = B> {
    pub stream_id: StreamId,
    pub offset: VarInt,
    pub header: Option<LenBytes<H>>,
    pub fin: bool,
    pub bytes: B,
}

impl<B, H> StreamData<B, H> {
    pub const MIN_WIRE_SIZE: usize = StreamId::MAX_ENCODED_LEN
        + VarInt::MAX_SIZE
        + size_of::<u8>()
        + VarInt::MAX_SIZE
        + VarInt::MAX_SIZE;
}

impl<B: ByteSlice> WireDecode<B> for StreamData<B> {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        let stream_id = reader.decode()?;
        let offset: VarInt = reader.decode()?;
        let flags = reader.decode::<u8>()?;
        let fin = (flags & flag::FIN) != 0;
        let has_header = (flags & flag::HEADER) != 0;
        let header = if has_header {
            Some(reader.decode()?)
        } else {
            None
        };
        let bytes = reader.decode::<LenBytes<B>>()?.0;

        Ok(Self {
            stream_id,
            offset,
            header,
            fin,
            bytes,
        })
    }
}

impl<B, H> StreamData<B, H> {
    pub fn into_owned(self) -> StreamData<Vec<u8>>
    where
        B: ByteSlice,
        H: ByteSlice,
    {
        StreamData {
            stream_id: self.stream_id,
            offset: self.offset,
            header: self.header.map(|header| LenBytes(header.0.to_vec())),
            fin: self.fin,
            bytes: self.bytes.to_vec(),
        }
    }
}

impl<B: BufView, H: BufView> WireEncode for StreamData<B, H> {
    fn encoded_len(&self) -> usize {
        self.stream_id.encoded_len()
            + self.offset.encoded_len()
            + size_of::<u8>()
            + self.header.as_ref().map_or(0, WireEncode::encoded_len)
            + LenBytes(&self.bytes).encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        debug_assert!(
            self.offset.into_inner() == 0 || self.header.is_none(),
            "stream header is only valid at offset 0"
        );

        self.stream_id.encode(out);
        self.offset.encode(out);
        let mut flags = 0;
        if self.fin {
            flags |= flag::FIN;
        }
        if self.header.is_some() {
            flags |= flag::HEADER;
        }
        flags.encode(out);
        if let Some(header) = &self.header {
            header.encode(out);
        }
        LenBytes(&self.bytes).encode(out);
    }
}

mod flag {
    pub const FIN: u8 = 0x01;
    pub const HEADER: u8 = 0x02;
}
