use crate::api::quantum_link::QuantumLink;
use flutter_rust_bridge::frb;
use {
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::quantum_link,
};

#[quantum_link]
pub struct Settings {
    #[n(0)]
    pub magic_backup: bool,
}

impl Settings {
    pub fn new(magic_backup: bool) -> Self {
        Self { magic_backup }
    }

    pub fn magic_backup(&self) -> bool {
        self.magic_backup
    }
}
