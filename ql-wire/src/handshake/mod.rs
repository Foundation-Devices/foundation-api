use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    codec::{push_value, read_exact},
    control::{control_meta_from_wire, control_meta_to_wire, ControlMetaWire},
    encrypted_message::{EncryptedMessage, EncryptedMessageRef},
    ControlMeta, MlDsaPublicKey, MlDsaSignature, MlKemCiphertext, Nonce, WireError,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloReply {
    pub meta: ControlMeta,
    pub nonce: Nonce,
    pub kem_ct: MlKemCiphertext,
    pub signature: MlDsaSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirm {
    pub meta: ControlMeta,
    pub signature: MlDsaSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    pub encrypted: EncryptedMessage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyBody {
    pub meta: ControlMeta,
}

pub type ReadyRef<B> = EncryptedMessageRef<B>;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct HelloWire {
    meta: ControlMetaWire,
    nonce: [u8; Nonce::SIZE],
    kem_ct: [u8; MlKemCiphertext::SIZE],
    signature: [u8; MlDsaSignature::SIZE],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct ConfirmWire {
    meta: ControlMetaWire,
    signature: [u8; MlDsaSignature::SIZE],
}

impl Hello {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        let wire = HelloWire {
            meta: control_meta_to_wire(&self.meta),
            nonce: self.nonce.0,
            kem_ct: *self.kem_ct.as_bytes(),
            signature: *self.signature.as_bytes(),
        };
        push_value(out, &wire);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let wire: HelloWire = read_exact(bytes)?;
        Ok(Self {
            meta: control_meta_from_wire(wire.meta),
            nonce: Nonce(wire.nonce),
            kem_ct: MlKemCiphertext::from_data(wire.kem_ct),
            signature: MlDsaSignature::from_data(wire.signature),
        })
    }
}

impl HelloReply {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        Hello {
            meta: self.meta,
            nonce: self.nonce,
            kem_ct: self.kem_ct.clone(),
            signature: self.signature.clone(),
        }
        .encode_into(out);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let hello = Hello::decode(bytes)?;
        Ok(Self {
            meta: hello.meta,
            nonce: hello.nonce,
            kem_ct: hello.kem_ct,
            signature: hello.signature,
        })
    }
}

impl Confirm {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        let wire = ConfirmWire {
            meta: control_meta_to_wire(&self.meta),
            signature: *self.signature.as_bytes(),
        };
        push_value(out, &wire);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let wire: ConfirmWire = read_exact(bytes)?;
        Ok(Self {
            meta: control_meta_from_wire(wire.meta),
            signature: MlDsaSignature::from_data(wire.signature),
        })
    }
}

impl Ready {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        self.encrypted.encode_into(out);
    }
}

impl ReadyBody {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let wire = control_meta_to_wire(&self.meta);
        wire.as_bytes().to_vec()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let wire: ControlMetaWire = read_exact(bytes)?;
        Ok(Self {
            meta: control_meta_from_wire(wire),
        })
    }
}

pub fn verify_signature(
    signing_key: &MlDsaPublicKey,
    signature: &MlDsaSignature,
    proof_data: &[u8],
) -> Result<(), WireError> {
    if signing_key.verify(signature, proof_data) {
        Ok(())
    } else {
        Err(WireError::InvalidSignature)
    }
}
