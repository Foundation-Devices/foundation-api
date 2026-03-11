use rkyv::{Archive, Deserialize, Serialize};

use crate::MessageId;

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HeartbeatBody {
    pub message_id: MessageId,
    pub valid_until: u64,
}
