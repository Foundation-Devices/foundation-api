use crate::quantum_link::QuantumLink;
use {
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::QuantumLink,
};

#[derive(Clone, Encode, Decode, QuantumLink, Debug)]
pub struct FirmwareUpdate {
    #[n(0)]
    version: String,
    #[n(1)]
    timestamp: u32,
    #[n(2)]
    changelog: String,
}

impl FirmwareUpdate {
    pub fn new(version: String, timestamp: u32, changelog: String) -> Self {
        Self {
            version,
            timestamp,
            changelog,
        }
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    pub fn changelog(&self) -> &str {
        &self.changelog
    }
}
