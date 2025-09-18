use crate::api::quantum_link::QuantumLink;
use flutter_rust_bridge::frb;
use {
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::quantum_link,
};

#[quantum_link]
pub struct Shard {
    #[n(0)]
    pub payload: Vec<u8>,
}

#[quantum_link]
pub struct BackupShardRequest(#[n(0)] pub Shard);

#[quantum_link]
pub enum BackupShardResponse {
    #[n(0)]
    Success,
    #[n(1)]
    Error(#[n(0)] String),
}

#[quantum_link]
pub struct RestoreShardRequest {
    #[n(0)]
    pub seed_fingerprint: [u8; 32],
}

#[quantum_link]
pub enum RestoreShardResponse {
    #[n(0)]
    Success(#[n(0)] Shard),
    #[n(1)]
    Error(#[n(0)] String),
    #[n(2)]
    NotFound(#[n(0)] String),
}

#[quantum_link]
pub struct MagicBackupEnabledRequest {}

#[quantum_link]
pub struct MagicBackupEnabledResponse {
    #[n(0)]
    enabled: bool,
}
