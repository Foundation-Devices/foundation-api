use rkyv::{Archive, Deserialize, Serialize};

use crate::PacketId;

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HeartbeatBody {
    pub packet_id: PacketId,
    pub valid_until: u64,
}
