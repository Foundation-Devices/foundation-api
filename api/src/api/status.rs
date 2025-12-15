use quantum_link_macros::quantum_link;

#[quantum_link]
pub struct DeviceStatus {
    #[n(0)]
    pub version: String,
    #[n(1)]
    pub battery_level: u8,
}

#[quantum_link]
pub struct EnvoyStatus {
    #[n(0)]
    pub version: String,
}

#[quantum_link]
pub struct Heartbeat {}
