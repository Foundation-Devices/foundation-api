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

#[quantum_link]
pub struct TimezoneRequest {}

#[quantum_link]
pub struct TimezoneResponse {
    #[n(0)]
    pub offset_minutes: i32,
    #[n(1)]
    pub zone: String,
}
