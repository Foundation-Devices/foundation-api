use rkyv::{Archive, Deserialize, Serialize};

use super::ControlMeta;

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HeartbeatBody {
    pub meta: ControlMeta,
}
