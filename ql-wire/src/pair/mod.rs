use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    codec::{push_value, read_exact, read_prefix, read_prefix_mut},
    control_meta_from_wire, control_meta_to_wire,
    encrypted_message::{EncryptedMessage, EncryptedMessageMut, EncryptedMessageRef},
    ControlMeta, MlDsaPublicKey, MlDsaSignature, MlKemCiphertext, MlKemPublicKey, WireError, XID,
};

mod crypto;
pub use crypto::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairRequestRecord {
    pub kem_ct: MlKemCiphertext,
    pub encrypted: EncryptedMessage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairRequestBody {
    pub meta: ControlMeta,
    pub xid: XID,
    pub signing_pub_key: MlDsaPublicKey,
    pub encapsulation_pub_key: MlKemPublicKey,
    pub proof: MlDsaSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairRequestRecordRef<'a> {
    pub kem_ct: MlKemCiphertext,
    pub encrypted: EncryptedMessageRef<'a>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PairRequestRecordMut<'a> {
    pub kem_ct: MlKemCiphertext,
    pub encrypted: EncryptedMessageMut<'a>,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct PairRequestHeaderWire {
    kem_ct: [u8; MlKemCiphertext::SIZE],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct PairRequestBodyWire {
    meta: crate::ControlMetaWire,
    xid: [u8; crate::XID_SIZE],
    signing_pub_key: [u8; MlDsaPublicKey::SIZE],
    encapsulation_pub_key: [u8; MlKemPublicKey::SIZE],
    proof: [u8; MlDsaSignature::SIZE],
}

impl PairRequestRecord {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        let header = PairRequestHeaderWire {
            kem_ct: *self.kem_ct.as_bytes(),
        };
        push_value(out, &header);
        self.encrypted.encode_into(out);
    }
}

impl<'a> PairRequestRecordRef<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, WireError> {
        let (header, payload) = read_prefix::<PairRequestHeaderWire>(bytes)?;
        Ok(Self {
            kem_ct: MlKemCiphertext::from_data(header.kem_ct),
            encrypted: EncryptedMessageRef::parse(payload)?,
        })
    }

    pub fn to_owned(&self) -> PairRequestRecord {
        PairRequestRecord {
            kem_ct: self.kem_ct,
            encrypted: self.encrypted.to_owned(),
        }
    }
}

impl<'a> PairRequestRecordMut<'a> {
    pub(crate) fn parse(bytes: &'a mut [u8]) -> Result<Self, WireError> {
        let (header, payload) = read_prefix_mut::<PairRequestHeaderWire>(bytes)?;
        Ok(Self {
            kem_ct: MlKemCiphertext::from_data(header.kem_ct),
            encrypted: EncryptedMessageMut::parse(payload)?,
        })
    }

    pub fn to_owned(&self) -> PairRequestRecord {
        PairRequestRecord {
            kem_ct: self.kem_ct,
            encrypted: self.encrypted.to_owned(),
        }
    }
}

impl PairRequestBody {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let wire = PairRequestBodyWire {
            meta: control_meta_to_wire(&self.meta),
            xid: self.xid,
            signing_pub_key: *self.signing_pub_key.as_bytes(),
            encapsulation_pub_key: *self.encapsulation_pub_key.as_bytes(),
            proof: *self.proof.as_bytes(),
        };
        wire.as_bytes().to_vec()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let wire: PairRequestBodyWire = read_exact(bytes)?;
        Ok(Self {
            meta: control_meta_from_wire(wire.meta),
            xid: wire.xid,
            signing_pub_key: MlDsaPublicKey::from_data(wire.signing_pub_key),
            encapsulation_pub_key: MlKemPublicKey::from_data(wire.encapsulation_pub_key),
            proof: MlDsaSignature::from_data(wire.proof),
        })
    }
}
