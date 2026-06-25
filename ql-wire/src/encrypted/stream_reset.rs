use ql_common::ResetCode;

use super::StreamId;
use crate::{codec, ByteSlice, WireEncode, WireError};

/// aborts one or both lanes of a stream with a reset code
///
/// stream origin is the peer that opened the stream
/// origin lane carries bytes sent by the stream origin
/// return lane carries bytes sent back toward the stream origin
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamReset {
    pub stream_id: StreamId,
    pub target: ResetTarget,
    pub code: ResetCode,
}

impl StreamReset {}

impl WireEncode for StreamReset {
    fn encoded_len(&self) -> usize {
        self.stream_id.encoded_len() + self.target.encoded_len() + self.code.encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.stream_id.encode(out);
        self.target.encode(out);
        self.code.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for StreamReset {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            stream_id: reader.decode()?,
            target: reader.decode()?,
            code: reader.decode()?,
        })
    }
}

/// selects which stream lane a [`StreamReset`] applies to
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResetTarget {
    /// reset the lane sent by the stream origin
    Origin = 1,
    /// reset the lane sent back toward the stream origin
    Return = 2,
    /// reset both stream lanes
    Both = 3,
}

impl ResetTarget {
    pub const fn to_wire(self) -> u8 {
        self as u8
    }
}

impl WireEncode for ResetTarget {
    fn encoded_len(&self) -> usize {
        size_of::<u8>()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.to_wire().encode(out);
    }
}

impl TryFrom<u8> for ResetTarget {
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

impl<B: ByteSlice> codec::WireDecode<B> for ResetTarget {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        reader.decode::<u8>()?.try_into()
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for ResetCode {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self(reader.decode()?))
    }
}

impl WireEncode for ResetCode {
    fn encoded_len(&self) -> usize {
        size_of::<u16>()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}
