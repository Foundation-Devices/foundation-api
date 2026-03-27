use std::mem::size_of;

use zerocopy::{
    byte_slice::ByteSlice, FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned,
};

use super::CloseCode;
use crate::{
    codec::{parse, push_value, read_exact, U16Le},
    WireError,
};

/// closes the whole session immediately with a close code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCloseBody {
    pub code: CloseCode,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct SessionCloseBodyWire {
    pub code: U16Le,
}

impl SessionCloseBody {
    pub const WIRE_SIZE: usize = size_of::<SessionCloseBodyWire>();

    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, SessionCloseBodyWire>, WireError> {
        if bytes.len() != Self::WIRE_SIZE {
            return Err(WireError::InvalidPayload);
        }
        parse(bytes)
    }

    pub fn from_wire(wire: &SessionCloseBodyWire) -> Self {
        Self {
            code: CloseCode(wire.code.get()),
        }
    }

    pub fn to_wire(&self) -> SessionCloseBodyWire {
        SessionCloseBodyWire {
            code: U16Le::new(self.code.0),
        }
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        push_value(out, &self.to_wire());
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let wire: SessionCloseBodyWire = read_exact(bytes)?;
        Ok(Self::from_wire(&wire))
    }
}
