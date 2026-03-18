use zerocopy::{
    byte_slice::ByteSlice, FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned,
};

use crate::{
    codec::{parse, push_value, read_exact},
    control::ControlMetaWire,
    encrypted_message::{EncryptedMessage, EncryptedMessageWire},
    ControlMeta, MlDsaSignature, MlKemCiphertext, Nonce, WireError,
};

mod crypto;
pub use crypto::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub meta: ControlMeta,
    pub nonce: Nonce,
    pub kem_ct: MlKemCiphertext,
    pub signature: MlDsaSignature,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct HelloWire {
    pub meta: ControlMetaWire,
    pub nonce: [u8; Nonce::SIZE],
    pub kem_ct: [u8; MlKemCiphertext::SIZE],
    pub signature: [u8; MlDsaSignature::SIZE],
}

impl Hello {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, HelloWire>, WireError> {
        parse(bytes)
    }

    pub fn from_wire(wire: &HelloWire) -> Self {
        Self {
            meta: ControlMeta::from_wire(wire.meta),
            nonce: Nonce(wire.nonce),
            kem_ct: MlKemCiphertext::from_data(wire.kem_ct),
            signature: MlDsaSignature::from_data(wire.signature),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let wire = Self::parse(bytes)?;
        Ok(Self::from_wire(&wire))
    }

    pub fn to_wire(&self) -> HelloWire {
        HelloWire {
            meta: self.meta.to_wire(),
            nonce: self.nonce.0,
            kem_ct: *self.kem_ct.as_bytes(),
            signature: *self.signature.as_bytes(),
        }
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        push_value(out, &self.to_wire());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloReply {
    pub meta: ControlMeta,
    pub nonce: Nonce,
    pub kem_ct: MlKemCiphertext,
    pub signature: MlDsaSignature,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct HelloReplyWire {
    pub meta: ControlMetaWire,
    pub nonce: [u8; Nonce::SIZE],
    pub kem_ct: [u8; MlKemCiphertext::SIZE],
    pub signature: [u8; MlDsaSignature::SIZE],
}

impl HelloReply {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, HelloReplyWire>, WireError> {
        parse(bytes)
    }

    pub fn from_wire(wire: &HelloReplyWire) -> Self {
        Self {
            meta: ControlMeta::from_wire(wire.meta),
            nonce: Nonce(wire.nonce),
            kem_ct: MlKemCiphertext::from_data(wire.kem_ct),
            signature: MlDsaSignature::from_data(wire.signature),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let wire = Self::parse(bytes)?;
        Ok(Self::from_wire(&wire))
    }

    pub fn to_wire(&self) -> HelloReplyWire {
        HelloReplyWire {
            meta: self.meta.to_wire(),
            nonce: self.nonce.0,
            kem_ct: *self.kem_ct.as_bytes(),
            signature: *self.signature.as_bytes(),
        }
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        push_value(out, &self.to_wire());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirm {
    pub meta: ControlMeta,
    pub signature: MlDsaSignature,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct ConfirmWire {
    pub meta: ControlMetaWire,
    pub signature: [u8; MlDsaSignature::SIZE],
}

impl Confirm {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, ConfirmWire>, WireError> {
        parse(bytes)
    }

    pub fn from_wire(wire: &ConfirmWire) -> Self {
        Self {
            meta: ControlMeta::from_wire(wire.meta),
            signature: MlDsaSignature::from_data(wire.signature),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let wire = Self::parse(bytes)?;
        Ok(Self::from_wire(&wire))
    }

    pub fn to_wire(&self) -> ConfirmWire {
        ConfirmWire {
            meta: self.meta.to_wire(),
            signature: *self.signature.as_bytes(),
        }
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        push_value(out, &self.to_wire());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    pub encrypted: EncryptedMessage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyBody {
    pub meta: ControlMeta,
}

impl Ready {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, EncryptedMessageWire>, WireError> {
        EncryptedMessage::parse(bytes)
    }

    pub fn from_wire(wire: &EncryptedMessageWire) -> Self {
        Self {
            encrypted: EncryptedMessage::from_wire(wire),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let wire = Self::parse(bytes)?;
        Ok(Self::from_wire(&wire))
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.encrypted.encode_into(out);
    }
}

impl ReadyBody {
    pub fn encode(&self) -> Vec<u8> {
        let wire = self.meta.to_wire();
        wire.as_bytes().to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let wire: ControlMetaWire = read_exact(bytes)?;
        Ok(Self {
            meta: ControlMeta::from_wire(wire),
        })
    }
}
