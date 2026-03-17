use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned};

use crate::{
    codec::{parse_mut, parse_ref, push_value, read_exact},
    control::{control_meta_from_wire, control_meta_to_wire, ControlMetaWire},
    encrypted_message::{
        EncryptedMessage, EncryptedMessageMut, EncryptedMessageRef, EncryptedMessageWire,
    },
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

pub type PairRequestRecordRef<'a> = Ref<&'a [u8], PairRequestRecordWire>;
pub type PairRequestRecordMut<'a> = Ref<&'a mut [u8], PairRequestRecordWire>;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
struct PairRequestBodyWire {
    meta: ControlMetaWire,
    xid: [u8; crate::XID_SIZE],
    signing_pub_key: [u8; MlDsaPublicKey::SIZE],
    encapsulation_pub_key: [u8; MlKemPublicKey::SIZE],
    proof: [u8; MlDsaSignature::SIZE],
}

impl PairRequestRecordWire {
    pub fn parse(bytes: &[u8]) -> Result<PairRequestRecordRef<'_>, WireError> {
        let record: PairRequestRecordRef<'_> = parse_ref(bytes)?;
        let _ = record.encrypted()?;
        Ok(record)
    }

    pub fn parse_mut(bytes: &mut [u8]) -> Result<PairRequestRecordMut<'_>, WireError> {
        let mut record: PairRequestRecordMut<'_> = parse_mut(bytes)?;
        let _ = record.encrypted_mut()?;
        Ok(record)
    }

    pub fn kem_ct(&self) -> MlKemCiphertext {
        MlKemCiphertext::from_data(self.kem_ct)
    }

    pub fn encrypted(&self) -> Result<EncryptedMessageRef<'_>, WireError> {
        EncryptedMessageWire::parse(&self.encrypted)
    }

    pub fn encrypted_mut(&mut self) -> Result<EncryptedMessageMut<'_>, WireError> {
        EncryptedMessageWire::parse_mut(&mut self.encrypted)
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
