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
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub(crate) struct ControlMetaWire {
    pub(crate) control_id: U32Le,
    pub(crate) valid_until: U64Le,
}

pub(crate) fn control_meta_to_wire(meta: &ControlMeta) -> ControlMetaWire {
    ControlMetaWire {
        control_id: U32Le::new(meta.control_id.0),
        valid_until: U64Le::new(meta.valid_until),
    }
}

pub(crate) fn control_meta_from_wire(meta: ControlMetaWire) -> ControlMeta {
    ControlMeta {
        control_id: ControlId(meta.control_id.get()),
        valid_until: meta.valid_until.get(),
    }
}
