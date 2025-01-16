use {
    crate::api::QuantumLinkMessage,
    minicbor_derive::{Decode, Encode},
};

#[derive(Clone, Encode, Decode)]
pub struct Settings {
    #[n(0)]
    magic_backup: bool,
}

impl Settings {
    pub fn new(magic_backup: bool) -> Self {
        Self { magic_backup }
    }

    pub fn magic_backup(&self) -> bool {
        self.magic_backup
    }
}

impl QuantumLinkMessage<Settings> for Settings {}
