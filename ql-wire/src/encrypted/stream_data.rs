use ql_codec::{
    encode_bytes, encoded_len_bytes, BufView, ByteSlice, Decode, Encode, Error, Varint,
};
use ql_common::StreamId;

/// carries bytes for a stream and may finish that sending direction
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamData<B, H = B> {
    pub stream_id: StreamId,
    pub offset: Varint<u64>,
    pub open: Option<StreamOpen<H>>,
    pub fin: bool,
    pub bytes: B,
}

/// parameters carried by the first frame of a stream
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOpen<H> {
    pub header: H,
    /// credit the opener grants the peer
    pub receive_window: Varint<u32>,
    /// credit the opener asks the peer to grant
    pub requested_peer_receive_window: Varint<u32>,
}

impl<B, H> StreamData<B, H> {
    /// largest framing overhead without an opening, excluding payload bytes
    pub const MAX_WIRE_OVERHEAD: usize = Varint::<u64>::MAX_ENCODED_LEN // stream id
        + Varint::<u64>::MAX_ENCODED_LEN // offset
        + size_of::<u8>() // flags
        + Varint::<u32>::MAX_ENCODED_LEN; // payload length

    /// largest framing overhead with an opening, excluding header and payload bytes
    pub const MAX_OPEN_WIRE_OVERHEAD: usize = Self::MAX_WIRE_OVERHEAD
        + Varint::<u32>::MAX_ENCODED_LEN // receive window
        + Varint::<u32>::MAX_ENCODED_LEN // requested peer receive window
        + Varint::<u32>::MAX_ENCODED_LEN; // header length
}

impl<B: ByteSlice> Decode<B> for StreamData<B> {
    fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, Error> {
        let stream_id = reader.decode()?;
        let offset = reader.decode()?;
        let flags = reader.decode::<u8>()?;
        let fin = (flags & flag::FIN) != 0;
        let has_open = (flags & flag::OPEN) != 0;
        let open = if has_open {
            Some(StreamOpen {
                receive_window: reader.decode()?,
                requested_peer_receive_window: reader.decode()?,
                header: reader.take_len_prefixed()?,
            })
        } else {
            None
        };
        let bytes = reader.take_len_prefixed()?;

        Ok(Self {
            stream_id,
            offset,
            open,
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
            open: self.open.map(|open| StreamOpen {
                header: open.header.to_vec(),
                receive_window: open.receive_window,
                requested_peer_receive_window: open.requested_peer_receive_window,
            }),
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
            + self.open.as_ref().map_or(0, |open| {
                open.receive_window.encoded_len()
                    + open.requested_peer_receive_window.encoded_len()
                    + encoded_len_bytes(&open.header)
            })
            + encoded_len_bytes(&self.bytes)
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        debug_assert!(
            *self.offset == 0 || self.open.is_none(),
            "stream opening is only valid at offset 0"
        );

        self.stream_id.encode(out);
        self.offset.encode(out);
        let mut flags = 0;
        if self.fin {
            flags |= flag::FIN;
        }
        if self.open.is_some() {
            flags |= flag::OPEN;
        }
        flags.encode(out);
        if let Some(open) = &self.open {
            open.receive_window.encode(out);
            open.requested_peer_receive_window.encode(out);
            encode_bytes(&open.header, out);
        }
        encode_bytes(&self.bytes, out);
    }
}

mod flag {
    pub const FIN: u8 = 0x01;
    pub const OPEN: u8 = 0x02;
}
