use {
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::quantum_link,
};
use crate::api::quantum_link::QuantumLink;
use flutter_rust_bridge::frb;

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
    pub state: DeviceState,
    #[n(1)]
    pub battery_level: u8,
    #[n(2)]
    pub ble_signal: i8,
    #[n(3)]
    pub version: String,
}

impl DeviceStatus {
    pub fn new(state: DeviceState, battery_level: u8, ble_signal: i8, version: String) -> Self {
        Self { state, battery_level, ble_signal, version }
    }
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
    pub state: EnvoyState,
    #[n(1)]
    pub version: String,
}
