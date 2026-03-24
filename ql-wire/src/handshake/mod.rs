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

pub trait HelloView {
    fn meta(&self) -> ControlMeta;
    fn nonce(&self) -> &[u8; Nonce::SIZE];
    fn kem_ct(&self) -> &[u8; MlKemCiphertext::SIZE];
    fn signature(&self) -> &[u8; MlDsaSignature::SIZE];
}

impl HelloView for Hello {
    fn meta(&self) -> ControlMeta {
        self.meta
    }

    fn nonce(&self) -> &[u8; Nonce::SIZE] {
        &self.nonce.0
    }

    fn kem_ct(&self) -> &[u8; MlKemCiphertext::SIZE] {
        self.kem_ct.as_bytes()
    }

    fn signature(&self) -> &[u8; MlDsaSignature::SIZE] {
        self.signature.as_bytes()
    }
}

impl<B: ByteSlice> HelloView for Ref<B, HelloWire> {
    fn meta(&self) -> ControlMeta {
        ControlMeta::from_wire(self.meta)
    }

    fn nonce(&self) -> &[u8; Nonce::SIZE] {
        &self.nonce
    }

    fn kem_ct(&self) -> &[u8; MlKemCiphertext::SIZE] {
        &self.kem_ct
    }

    fn signature(&self) -> &[u8; MlDsaSignature::SIZE] {
        &self.signature
    }
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

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        push_value(
            out,
            &HelloWire {
                meta: self.meta.to_wire(),
                nonce: self.nonce.0,
                kem_ct: *self.kem_ct.as_bytes(),
                signature: *self.signature.as_bytes(),
            },
        );
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

pub trait HelloReplyView {
    fn meta(&self) -> ControlMeta;
    fn nonce(&self) -> &[u8; Nonce::SIZE];
    fn kem_ct(&self) -> &[u8; MlKemCiphertext::SIZE];
    fn signature(&self) -> &[u8; MlDsaSignature::SIZE];
}

impl HelloReplyView for HelloReply {
    fn meta(&self) -> ControlMeta {
        self.meta
    }

    fn nonce(&self) -> &[u8; Nonce::SIZE] {
        &self.nonce.0
    }

    fn kem_ct(&self) -> &[u8; MlKemCiphertext::SIZE] {
        self.kem_ct.as_bytes()
    }

    fn signature(&self) -> &[u8; MlDsaSignature::SIZE] {
        self.signature.as_bytes()
    }
}

impl<B: ByteSlice> HelloReplyView for Ref<B, HelloReplyWire> {
    fn meta(&self) -> ControlMeta {
        ControlMeta::from_wire(self.meta)
    }

    fn nonce(&self) -> &[u8; Nonce::SIZE] {
        &self.nonce
    }

    fn kem_ct(&self) -> &[u8; MlKemCiphertext::SIZE] {
        &self.kem_ct
    }

    fn signature(&self) -> &[u8; MlDsaSignature::SIZE] {
        &self.signature
    }
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

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        push_value(
            out,
            &HelloReplyWire {
                meta: self.meta.to_wire(),
                nonce: self.nonce.0,
                kem_ct: *self.kem_ct.as_bytes(),
                signature: *self.signature.as_bytes(),
            },
        );
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

pub trait ConfirmView {
    fn meta(&self) -> ControlMeta;
    fn signature(&self) -> &[u8; MlDsaSignature::SIZE];
}

impl ConfirmView for Confirm {
    fn meta(&self) -> ControlMeta {
        self.meta
    }

    fn signature(&self) -> &[u8; MlDsaSignature::SIZE] {
        self.signature.as_bytes()
    }
}

impl<B: ByteSlice> ConfirmView for Ref<B, ConfirmWire> {
    fn meta(&self) -> ControlMeta {
        ControlMeta::from_wire(self.meta)
    }

    fn signature(&self) -> &[u8; MlDsaSignature::SIZE] {
        &self.signature
    }
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

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        push_value(
            out,
            &ConfirmWire {
                meta: self.meta.to_wire(),
                signature: *self.signature.as_bytes(),
            },
        );
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
