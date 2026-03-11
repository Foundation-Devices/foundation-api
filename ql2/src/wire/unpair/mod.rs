use bc_components::MLDSASignature;
use rkyv::{Archive, Deserialize, Serialize};

use super::AsWireMlDsaSignature;
use crate::PacketId;

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct UnpairRecord {
    pub packet_id: PacketId,
    pub valid_until: u64,
    #[rkyv(with = AsWireMlDsaSignature)]
    pub signature: MLDSASignature,
}
