use rkyv::{Archive, Deserialize, Serialize};

#[derive(
    Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub struct XID(pub [u8; Self::XID_SIZE]);

impl XID {
    // todo: change to 16 bytes
    pub const XID_SIZE: usize = 32;
}
