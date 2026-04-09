use super::{RouteId, StreamId};
use crate::{codec, ByteChunks, ByteSlice, VarInt, WireDecode, WireEncode, WireError};

/// carries bytes for a stream and may finish that sending direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamData<B> {
    pub stream_id: StreamId,
    pub offset: VarInt,
    pub header: Option<StreamHeader>,
    pub fin: bool,
    pub bytes: B,
}

impl<B> StreamData<B> {
    pub const MIN_WIRE_SIZE: usize = StreamId::MAX_ENCODED_LEN
        + VarInt::MAX_SIZE
        + size_of::<u8>()
        + StreamHeader::MAX_WIRE_SIZE;
}

impl<B: ByteSlice> WireDecode<B> for StreamData<B> {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        let stream_id = reader.decode()?;
        let offset: VarInt = reader.decode()?;
        let flags = reader.decode::<u8>()?;
        let fin = (flags & flag::FIN) != 0;
        let has_header = (flags & flag::HEADER) != 0;

        Ok(Self {
            stream_id,
            offset,
            header: if has_header {
                Some(reader.decode()?)
            } else {
                None
            },
            fin,
            bytes: reader.take_rest(),
        })
    }
}

impl<B> StreamData<B> {
    pub fn into_owned(self) -> StreamData<Vec<u8>>
    where
        B: ByteSlice,
    {
        StreamData {
            stream_id: self.stream_id,
            offset: self.offset,
            header: self.header,
            fin: self.fin,
            bytes: self.bytes.to_vec(),
        }
    }
}

impl<B: ByteChunks> WireEncode for StreamData<B> {
    fn encoded_len(&self) -> usize {
        self.stream_id.encoded_len()
            + self.offset.encoded_len()
            + size_of::<u8>()
            + self.header.as_ref().map_or(0, WireEncode::encoded_len)
            + self.bytes.len()
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
        for chunk in self.bytes.chunks() {
            chunk.encode(out);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamHeader {
    pub route_id: RouteId,
}

impl StreamHeader {
    pub const MAX_WIRE_SIZE: usize = RouteId::MAX_ENCODED_LEN;
}

impl<B: ByteSlice> WireDecode<B> for StreamHeader {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            route_id: reader.decode()?,
        })
    }
}

impl WireEncode for StreamHeader {
    fn encoded_len(&self) -> usize {
        self.route_id.encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.route_id.encode(out);
    }
}

mod flag {
    pub const FIN: u8 = 0x01;
    pub const HEADER: u8 = 0x02;
}
