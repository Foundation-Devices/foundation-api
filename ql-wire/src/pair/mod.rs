use zerocopy::{
    byte_slice::{ByteSlice, ByteSliceMut},
    FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned,
};

use crate::{
    codec::{parse, push_value, read_exact},
    control::{control_meta_from_wire, control_meta_to_wire, ControlMetaWire},
    encrypted_message::{EncryptedMessage, EncryptedMessageRef},
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

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct PairRequestRecordWire {
    pub kem_ct: [u8; MlKemCiphertext::SIZE],
    pub encrypted: [u8],
}

pub struct PairRequestRecordRef<B> {
    wire: Ref<B, PairRequestRecordWire>,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct PairRequestBodyWire {
    meta: ControlMetaWire,
    xid: [u8; XID::SIZE],
    signing_pub_key: [u8; MlDsaPublicKey::SIZE],
    encapsulation_pub_key: [u8; MlKemPublicKey::SIZE],
    proof: [u8; MlDsaSignature::SIZE],
}

impl<B: ByteSlice> PairRequestRecordRef<B> {
    pub fn parse(bytes: B) -> Result<Self, WireError> {
        let record = Self {
            wire: parse(bytes)?,
        };
        let _ = record.encrypted()?;
        Ok(record)
    }

    pub fn kem_ct(&self) -> MlKemCiphertext {
        MlKemCiphertext::from_data(self.wire.kem_ct)
    }

    pub fn encrypted(&self) -> Result<EncryptedMessageRef<&[u8]>, WireError> {
        EncryptedMessageRef::parse(&self.wire.encrypted)
    }

    pub fn to_pair_request_record(&self) -> PairRequestRecord {
        PairRequestRecord {
            kem_ct: self.kem_ct(),
            encrypted: self
                .encrypted()
                .expect("validated pair request")
                .to_encrypted_message(),
        }
    }
}

impl<B: ByteSliceMut> PairRequestRecordRef<B> {
    pub fn encrypted_mut(&mut self) -> Result<EncryptedMessageRef<&mut [u8]>, WireError> {
        EncryptedMessageRef::parse(&mut self.wire.encrypted)
    }
}

impl PairRequestRecord {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        push_value(
            out,
            &PairRequestHeaderWire {
                kem_ct: *self.kem_ct.as_bytes(),
            },
        );
        out.extend_from_slice(&self.encrypted.encode());
    }
}

impl PairRequestBody {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let wire = PairRequestBodyWire {
            meta: control_meta_to_wire(&self.meta),
            xid: self.xid.0,
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
            xid: XID(wire.xid),
            signing_pub_key: MlDsaPublicKey::from_data(wire.signing_pub_key),
            encapsulation_pub_key: MlKemPublicKey::from_data(wire.encapsulation_pub_key),
            proof: MlDsaSignature::from_data(wire.proof),
        })
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct PairRequestHeaderWire {
    kem_ct: [u8; MlKemCiphertext::SIZE],
}
