use bc_components::{MLDSAPublicKey, SigningPublicKey};
use rkyv::{Archive, Deserialize, Serialize};

#[derive(
    Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub struct XID(pub [u8; Self::XID_SIZE]);

impl XID {
    pub const XID_SIZE: usize = 32;

    pub fn from_signing_public_key(signing_public_key: &MLDSAPublicKey) -> Self {
        let xid = bc_components::XID::new(SigningPublicKey::MLDSA(signing_public_key.clone()));
        Self(*xid.data())
    }
}
