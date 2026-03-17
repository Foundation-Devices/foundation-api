use rkyv::{Archive, Deserialize, Serialize};

use crate::{
    encrypted_message::EncryptedMessage, ControlMeta, MlDsaPublicKey, MlDsaSignature,
    MlKemCiphertext, MlKemPublicKey, XID,
};

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PairRequestRecord {
    pub kem_ct: MlKemCiphertext,
    pub encrypted: EncryptedMessage,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PairRequestBody {
    pub meta: ControlMeta,
    pub xid: XID,
    pub signing_pub_key: MlDsaPublicKey,
    pub encapsulation_pub_key: MlKemPublicKey,
    pub proof: MlDsaSignature,
}
