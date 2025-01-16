use {
    crate::api::QuantumLinkMessage,
    minicbor_derive::{Decode, Encode},
};

#[derive(Clone, Encode, Decode)]
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
        Self { version, timestamp, changelog }
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

impl QuantumLinkMessage<FirmwareUpdate> for FirmwareUpdate {}
