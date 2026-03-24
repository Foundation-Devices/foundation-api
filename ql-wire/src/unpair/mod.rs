use zerocopy::{
    byte_slice::ByteSlice, FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned,
};

use crate::{
    codec::{parse, push_value},
    control::ControlMetaWire,
    ControlMeta, MlDsaSignature, WireError,
};

mod crypto;
pub use crypto::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unpair {
    pub meta: ControlMeta,
    pub signature: MlDsaSignature,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct UnpairWire {
    pub meta: ControlMetaWire,
    pub signature: [u8; MlDsaSignature::SIZE],
}

impl Unpair {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, UnpairWire>, WireError> {
        parse(bytes)
    }

    pub fn from_wire(wire: &UnpairWire) -> Self {
        Self {
            meta: ControlMeta::from_wire(wire.meta),
            signature: MlDsaSignature::from_data(wire.signature),
        }
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        push_value(
            out,
            &UnpairWire {
                meta: self.meta.to_wire(),
                signature: *self.signature.as_bytes(),
            },
        );
    }
}
