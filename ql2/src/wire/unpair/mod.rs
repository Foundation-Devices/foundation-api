use bc_components::MLDSASignature;
use rkyv::{Archive, Deserialize, Serialize};

use super::{AsWireMlDsaSignature, ControlMeta};

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct UnpairRecord {
    pub meta: ControlMeta,
    #[rkyv(with = AsWireMlDsaSignature)]
    pub signature: MLDSASignature,
}
