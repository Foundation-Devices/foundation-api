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
struct SessionCloseBodyWire {
    code: U16Le,
}

impl SessionCloseBody {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        let wire = SessionCloseBodyWire {
            code: U16Le::new(self.code.0),
        };
        push_value(out, &wire);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let wire: SessionCloseBodyWire = read_exact(bytes)?;
        Ok(Self {
            code: CloseCode(wire.code.get()),
        })
    }
}
