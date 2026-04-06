use super::StreamId;
use crate::{codec, ByteSlice, WireEncode, WireError};

/// aborts one or both lanes of a stream with a close code
///
/// stream origin is the peer that opened the stream
/// origin lane carries bytes sent by the stream origin
/// return lane carries bytes sent back toward the stream origin
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamClose {
    pub stream_id: StreamId,
    pub target: CloseTarget,
    pub code: StreamCloseCode,
}

impl StreamClose {}

impl WireEncode for StreamClose {
    fn encoded_len(&self) -> usize {
        self.stream_id.encoded_len() + self.target.encoded_len() + self.code.encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.stream_id.encode(out);
        self.target.encode(out);
        self.code.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for StreamClose {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            stream_id: reader.decode()?,
            target: reader.decode()?,
            code: reader.decode()?,
        })
    }
}

/// selects which stream lane a [`StreamClose`] applies to
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseTarget {
    /// close the lane sent by the stream origin
    Origin = 1,
    /// close the lane sent back toward the stream origin
    Return = 2,
    /// close both stream lanes
    Both = 3,
}

impl CloseTarget {
    pub const fn to_wire(self) -> u8 {
        self as u8
    }
}

impl WireEncode for CloseTarget {
    fn encoded_len(&self) -> usize {
        size_of::<u8>()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.to_wire().encode(out);
    }
}

impl TryFrom<u8> for CloseTarget {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Origin),
            2 => Ok(Self::Return),
            3 => Ok(Self::Both),
            _ => Err(WireError::InvalidPayload),
        }
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for CloseTarget {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        reader.decode::<u8>()?.try_into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct StreamCloseCode(pub u16);

impl<B: ByteSlice> codec::WireDecode<B> for StreamCloseCode {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self(reader.decode()?))
    }
}

impl WireEncode for StreamCloseCode {
    fn encoded_len(&self) -> usize {
        size_of::<u16>()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}
