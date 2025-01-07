use minicbor_derive::{Decode, Encode};

#[derive(Clone, Encode, Decode)]
pub enum PassportModel {
    #[n(0)]
    Gen1,
    #[n(1)]
    Gen2,
    #[n(2)]
    Prime,
}

#[derive(Clone, Encode, Decode)]
pub struct PassportFirmwareVersion(#[n(0)] pub String);

#[derive(Clone, Encode, Decode)]
pub struct PassportSerial(#[n(0)] pub String);
