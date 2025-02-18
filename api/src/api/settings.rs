use {
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::QuantumLink,
};
use crate::api::quantum_link::QuantumLink;

#[derive(Clone, Encode, Decode, QuantumLink)]
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
