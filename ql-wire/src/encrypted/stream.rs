use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    codec::{push_value, read_prefix, U16Le, U32Le, U64Le},
    StreamId, WireError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFrame {
    pub stream_id: StreamId,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub fin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCloseFrame {
    pub stream_id: StreamId,
    pub target: CloseTarget,
    pub code: CloseCode,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseTarget {
    Request = 1,
    Response = 2,
    Both = 3,
}

impl CloseTarget {
    pub(crate) fn from_wire(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Both),
            _ => Err(WireError::InvalidPayload),
        }
    }

    pub(crate) const fn to_wire(self) -> u8 {
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

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct StreamFrameHeaderWire {
    stream_id: U32Le,
    offset: U64Le,
    fin: u8,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct StreamCloseHeaderWire {
    stream_id: U32Le,
    target: u8,
    code: U16Le,
}

impl StreamFrame {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        let header = StreamFrameHeaderWire {
            stream_id: U32Le::new(self.stream_id),
            offset: U64Le::new(self.offset),
            fin: u8::from(self.fin),
        };
        push_value(out, &header);
        out.extend_from_slice(&self.bytes);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (header, payload) = read_prefix::<StreamFrameHeaderWire>(bytes)?;
        let fin = match header.fin {
            0 => false,
            1 => true,
            _ => return Err(WireError::InvalidPayload),
        };
        Ok(Self {
            stream_id: header.stream_id.get(),
            offset: header.offset.get(),
            bytes: payload.to_vec(),
            fin,
        })
    }
}

impl StreamCloseFrame {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        let header = StreamCloseHeaderWire {
            stream_id: U32Le::new(self.stream_id),
            target: self.target.to_wire(),
            code: U16Le::new(self.code.0),
        };
        push_value(out, &header);
        out.extend_from_slice(&self.payload);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (header, payload) = read_prefix::<StreamCloseHeaderWire>(bytes)?;
        Ok(Self {
            stream_id: header.stream_id.get(),
            target: CloseTarget::from_wire(header.target)?,
            code: CloseCode(header.code.get()),
            payload: payload.to_vec(),
        })
    }
}
