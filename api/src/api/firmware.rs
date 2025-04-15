use quantum_link_macros::quantum_link;
use crate::quantum_link::QuantumLink;
use {
    minicbor_derive::{Decode, Encode},
};
use flutter_rust_bridge::frb;


#[quantum_link]
pub struct FirmwareUpdate {
    #[n(0)]
    pub version: String,
    #[n(1)]
    pub timestamp: u32,
    #[n(2)]
    pub changelog: String,
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

#[quantum_link]
pub struct FirmwarePayload {
    #[n(0)]
    pub payload: Vec<u8>,
}

impl FirmwarePayload {
    pub fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }

    pub fn payload(&self) -> &Vec<u8> {
        &self.payload
    }
}

