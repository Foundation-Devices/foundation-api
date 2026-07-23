use ql_codec::{
    encode_bytes, encoded_len_bytes, BufView, ByteSlice, Decode, Encode, Error, Varint,
};
use ql_common::StreamId;

/// carries bytes for a stream and may finish that sending direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamData<B, H = B> {
    pub stream_id: StreamId,
    pub offset: Varint<u64>,
    pub header: Option<H>,
    pub fin: bool,
    pub bytes: B,
}

impl<B, H> StreamData<B, H> {
    /// Largest framing overhead of a stream data frame, excluding the header and payload bytes
    /// that its two length prefixes measure.
    ///
    /// The terms follow the field order in `encode`. Lengths are bounded as `u64` rather than
    /// `usize` so the figure does not shrink on a 32-bit target, where framing would otherwise
    /// differ from the host.
    pub const MAX_WIRE_OVERHEAD: usize = Varint::<u64>::MAX_ENCODED_LEN // stream id
        + Varint::<u64>::MAX_ENCODED_LEN // offset
        + size_of::<u8>() // flags
        + Varint::<u32>::MAX_ENCODED_LEN // header length
        + Varint::<u32>::MAX_ENCODED_LEN; // payload length
}

impl<B: ByteSlice> Decode<B> for StreamData<B> {
    fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, Error> {
        let stream_id = reader.decode()?;
        let offset = reader.decode()?;
        let flags = reader.decode::<u8>()?;
        let fin = (flags & flag::FIN) != 0;
        let has_header = (flags & flag::HEADER) != 0;
        let header = if has_header {
            Some(reader.take_len_prefixed()?)
        } else {
            None
        };
        let bytes = reader.take_len_prefixed()?;

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
            header: self.header.map(|header| header.to_vec()),
            fin: self.fin,
            bytes: self.bytes.to_vec(),
        }
    }
}

impl<B: BufView, H: BufView> Encode for StreamData<B, H> {
    fn encoded_len(&self) -> usize {
        self.stream_id.encoded_len()
            + self.offset.encoded_len()
            + size_of::<u8>()
            + self.header.as_ref().map_or(0, encoded_len_bytes)
            + encoded_len_bytes(&self.bytes)
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        debug_assert!(
            *self.offset == 0 || self.header.is_none(),
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
            encode_bytes(header, out);
        }
        encode_bytes(&self.bytes, out);
    }
}

mod flag {
    pub const FIN: u8 = 0x01;
    pub const HEADER: u8 = 0x02;
}
