use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::CloseCode;
use crate::{
    codec::{push_value, read_exact, U16Le},
    WireError,
};

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
    pub fn from_wire(wire: SessionCloseBodyWire) -> Self {
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
        Ok(Self::from_wire(wire))
    }
}
