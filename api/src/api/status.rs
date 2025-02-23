use {
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::quantum_link,
};
use crate::api::quantum_link::QuantumLink;

#[quantum_link]
pub enum DeviceState {
    #[n(0)]
    Normal,
    #[n(1)]
    UpdatingFirmware,
    #[n(2)]
    Rebooting,
}

#[quantum_link]
pub struct DeviceStatus {
    #[n(0)]
    state: DeviceState,
    #[n(1)]
    battery_level: u8,
    #[n(2)]
    ble_signal: u8,
    #[n(3)]
    version: String,
}

#[quantum_link]
pub enum EnvoyState {
    #[n(0)]
    Normal,
    #[n(1)]
    DownloadingFirmware,
}

#[quantum_link]
pub struct EnvoyStatus {
    #[n(0)]
    state: EnvoyState,
    #[n(1)]
    version: String,
}
