use std::mem::size_of;

use zerocopy::{
    byte_slice::ByteSlice, FromBytes, Immutable, IntoBytes, KnownLayout, Ref, TryFromBytes,
    Unaligned,
};

use super::StreamId;
use crate::{codec::{parse, read_byte, U16Le, U32Le}, WireError};

/// aborts one or both directions of a stream with a close code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamClose {
    pub stream_id: StreamId,
    pub target: CloseTarget,
    pub code: CloseCode,
    pub payload: Vec<u8>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, TryFromBytes, KnownLayout, Immutable, IntoBytes, Unaligned,
)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CloseCode(pub u16);

impl CloseCode {
    pub const CANCELLED: Self = Self(0);
    pub const PROTOCOL: Self = Self(1);
    pub const INVALID_DATA: Self = Self(2);
    pub const TIMEOUT: Self = Self(3);

    pub const UNKNOWN: Self = Self(16);
    pub const UNKNOWN_ROUTE: Self = Self(17);
    pub const INVALID_HEAD: Self = Self(18);
    pub const BUSY: Self = Self(19);
    pub const UNHANDLED: Self = Self(20);
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct StreamCloseWire {
    pub stream_id: U32Le,
    pub target: u8,
    pub code: U16Le,
    pub payload: [u8],
}

impl StreamClose {
    pub const MIN_WIRE_SIZE: usize =
        size_of::<U32Le>() + size_of::<u8>() + size_of::<U16Le>();

    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, StreamCloseWire>, WireError> {
        if bytes.len() < Self::MIN_WIRE_SIZE {
            return Err(WireError::InvalidPayload);
        }
        let wire: Ref<B, StreamCloseWire> = parse(bytes)?;
        let _ = read_byte::<CloseTarget>(wire.target)?;
        Ok(wire)
    }

    pub fn encoded_len(&self) -> usize {
        Self::MIN_WIRE_SIZE + self.payload.len()
    }

    pub fn from_wire(wire: &StreamCloseWire) -> Result<Self, WireError> {
        Ok(Self {
            stream_id: StreamId(wire.stream_id.get()),
            target: read_byte(wire.target)?,
            code: CloseCode(wire.code.get()),
            payload: wire.payload.to_vec(),
        })
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.stream_id.0.to_le_bytes());
        out.push(self.target.to_wire());
        out.extend_from_slice(&self.code.0.to_le_bytes());
        out.extend_from_slice(&self.payload);
    }
}
