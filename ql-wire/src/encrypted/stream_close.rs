use super::StreamId;
use crate::{codec, ByteSlice, WireError};

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

impl StreamClose {
    pub const WIRE_SIZE: usize =
        size_of::<StreamId>() + size_of::<CloseTarget>() + size_of::<StreamCloseCode>();

    pub fn encode_into(&self, out: &mut [u8]) {
        let out = codec::write_u32(out, self.stream_id.0);
        let out = codec::write_u8(out, self.target.to_wire());
        let _ = codec::write_u16(out, self.code.0);
    }
}

impl<B: ByteSlice> codec::WireParse<B> for StreamClose {
    fn parse(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            stream_id: StreamId(reader.take_u32()?),
            target: CloseTarget::try_from(reader.take_u8()?)?,
            code: StreamCloseCode(reader.take_u16()?),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct StreamCloseCode(pub u16);
