use std::mem::size_of;

use super::StreamId;
use crate::{codec, ByteSlice, WireError};

/// aborts one or both directions of a stream with a close code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamClose {
    pub stream_id: StreamId,
    pub target: CloseTarget,
    pub code: StreamCloseCode,
}

impl StreamClose {
    pub const WIRE_SIZE: usize =
        size_of::<StreamId>() + size_of::<CloseTarget>() + size_of::<StreamCloseCode>();

    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let close = Self {
            stream_id: StreamId(reader.take_u32()?),
            target: CloseTarget::try_from(reader.take_u8()?)?,
            code: StreamCloseCode(reader.take_u16()?),
        };
        reader.finish()?;
        Ok(close)
    }

    pub fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        codec::push_u32(out, self.stream_id.0);
        codec::push_u8(out, self.target.to_wire());
        codec::push_u16(out, self.code.0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseTarget {
    Request = 1,
    Response = 2,
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
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Both),
            _ => Err(WireError::InvalidPayload),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct StreamCloseCode(pub u16);
