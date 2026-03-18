use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    codec::{U32Le, U64Le},
    WireError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ControlId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlMeta {
    pub control_id: ControlId,
    pub valid_until: u64,
}

impl ControlMeta {
    pub fn ensure_not_expired(&self, now_seconds: u64) -> Result<(), WireError> {
        if now_seconds > self.valid_until {
            Err(WireError::Expired)
        } else {
            Ok(())
        }
    }

    pub fn to_wire(&self) -> ControlMetaWire {
        ControlMetaWire {
            control_id: U32Le::new(self.control_id.0),
            valid_until: U64Le::new(self.valid_until),
        }
    }

    pub fn from_wire(meta: ControlMetaWire) -> Self {
        Self {
            control_id: ControlId(meta.control_id.get()),
            valid_until: meta.valid_until.get(),
        }
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct ControlMetaWire {
    pub control_id: U32Le,
    pub valid_until: U64Le,
}
