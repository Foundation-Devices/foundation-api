use {
    minicbor_derive::{Decode, Encode},
    quantum_link_macros::QuantumLinkMessage,
};
use crate::api::quantum_link::QuantumLinkMessage;

#[derive(Clone, Encode, Decode, QuantumLinkMessage, Debug)]
pub enum DeviceState {
    #[n(0)]
    Normal,
    #[n(1)]
    UpdatingFirmware,
    #[n(2)]
    Rebooting,
}

#[derive(Clone, Encode, Decode, QuantumLinkMessage, Debug)]
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

#[derive(Clone, Encode, Decode, QuantumLinkMessage, Debug)]
pub enum EnvoyState {
    #[n(0)]
    Normal,
    #[n(1)]
    DownloadingFirmware,
}

#[derive(Clone, Encode, Decode, QuantumLinkMessage, Debug)]
pub struct EnvoyStatus {
    #[n(0)]
    state: EnvoyState,
    #[n(1)]
    version: String,
}
