use quantum_link_macros::quantum_link;

#[quantum_link]
pub enum PassportModel {
    #[n(0)]
    Gen1,
    #[n(1)]
    Gen2,
    #[n(2)]
    Prime,
}

#[quantum_link]
pub struct PassportFirmwareVersion(#[n(0)] pub String);

#[quantum_link]
pub struct PassportSerial(#[n(0)] pub String);

#[quantum_link]
pub enum PassportColor {
    #[n(0)]
    Light,
    #[n(1)]
    Dark,
}
