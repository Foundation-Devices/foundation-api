use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned};

use crate::{
    codec::{parse_mut, parse_ref, push_value, U16Le, U32Le},
    StreamId, WireError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamClose {
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

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct StreamCloseWire {
    pub stream_id: U32Le,
    pub target: u8,
    pub code: U16Le,
    pub payload: [u8],
}

pub type StreamCloseRef<'a> = Ref<&'a [u8], StreamCloseWire>;
pub type StreamCloseMut<'a> = Ref<&'a mut [u8], StreamCloseWire>;

impl StreamCloseWire {
    pub fn parse(bytes: &[u8]) -> Result<StreamCloseRef<'_>, WireError> {
        parse_ref(bytes)
    }

    pub fn parse_mut(bytes: &mut [u8]) -> Result<StreamCloseMut<'_>, WireError> {
        parse_mut(bytes)
    }

    pub fn target(&self) -> Result<CloseTarget, WireError> {
        CloseTarget::from_wire(self.target)
    }

    pub fn to_stream_close(&self) -> Result<StreamClose, WireError> {
        Ok(StreamClose {
            stream_id: self.stream_id.get(),
            target: self.target()?,
            code: CloseCode(self.code.get()),
            payload: self.payload.to_vec(),
        })
    }
}

impl StreamClose {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        let header = StreamCloseHeaderWire {
            stream_id: U32Le::new(self.stream_id),
            target: self.target.to_wire(),
            code: U16Le::new(self.code.0),
        };
        push_value(out, &header);
        out.extend_from_slice(&self.payload);
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct StreamCloseHeaderWire {
    stream_id: U32Le,
    target: u8,
    code: U16Le,
}
