use zerocopy::{
    byte_slice::ByteSlice, FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned,
};

use crate::{
    codec::{parse, push_value, read_exact},
    control::ControlMetaWire,
    encrypted_message::EncryptedMessage,
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
pub struct PairRequestRecordWire {
    pub kem_ct: [u8; MlKemCiphertext::SIZE],
    pub encrypted: [u8],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct PairRequestBodyWire {
    pub meta: ControlMetaWire,
    pub xid: [u8; XID::SIZE],
    pub signing_pub_key: [u8; MlDsaPublicKey::SIZE],
    pub encapsulation_pub_key: [u8; MlKemPublicKey::SIZE],
    pub proof: [u8; MlDsaSignature::SIZE],
}

impl PairRequestRecord {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<Ref<B, PairRequestRecordWire>, WireError> {
        let record: Ref<B, PairRequestRecordWire> = parse(bytes)?;
        let _ = EncryptedMessage::parse(&record.encrypted)?;
        Ok(record)
    }

    pub fn from_wire(wire: &PairRequestRecordWire) -> Self {
        let encrypted =
            EncryptedMessage::parse(&wire.encrypted).expect("validated pair request record");
        Self {
            kem_ct: MlKemCiphertext::from_data(wire.kem_ct),
            encrypted: EncryptedMessage::from_wire(&encrypted),
        }
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
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
    pub fn from_wire(wire: PairRequestBodyWire) -> Self {
        Self {
            meta: ControlMeta::from_wire(wire.meta),
            xid: XID(wire.xid),
            signing_pub_key: MlDsaPublicKey::from_data(wire.signing_pub_key),
            encapsulation_pub_key: MlKemPublicKey::from_data(wire.encapsulation_pub_key),
            proof: MlDsaSignature::from_data(wire.proof),
        }
    }

    pub fn to_wire(&self) -> PairRequestBodyWire {
        PairRequestBodyWire {
            meta: self.meta.to_wire(),
            xid: self.xid.0,
            signing_pub_key: *self.signing_pub_key.as_bytes(),
            encapsulation_pub_key: *self.encapsulation_pub_key.as_bytes(),
            proof: *self.proof.as_bytes(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let wire = self.to_wire();
        wire.as_bytes().to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let wire: PairRequestBodyWire = read_exact(bytes)?;
        Ok(Self::from_wire(wire))
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct PairRequestHeaderWire {
    pub kem_ct: [u8; MlKemCiphertext::SIZE],
}
