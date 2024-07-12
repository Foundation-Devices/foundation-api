use {
    anyhow::Error,
    bc_components::tag_constant,
    dcbor::{CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Tag, CBOR},
    paste::paste,
};

tag_constant!(PASSPORT_MODEL, 721, "passport-model");

#[repr(u8)]
#[derive(Clone)]
pub enum PassportModel {
    Gen1 = 1,
    Gen2 = 2,
    Prime = 3,
}

impl From<u8> for PassportModel {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Gen1,
            2 => Self::Gen2,
            3 => Self::Prime,
            _ => panic!("unknown passport model"),
        }
    }
}

impl From<&PassportModel> for u8 {
    fn from(value: &PassportModel) -> Self {
        value.clone() as u8
    }
}

impl CBORTagged for PassportModel {
    fn cbor_tags() -> Vec<Tag> {
        vec![PASSPORT_MODEL]
    }
}

impl CBORTaggedEncodable for PassportModel {
    fn untagged_cbor(&self) -> CBOR {
        let model_number: u8 = self.into();
        CBOR::from(model_number)
    }
}

impl TryFrom<CBOR> for PassportModel {
    type Error = Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(value)
    }
}

impl CBORTaggedDecodable for PassportModel {
    fn from_untagged_cbor(cbor: CBOR) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let model_number: u8 = cbor.try_into()?;
        Ok(PassportModel::from(model_number))
    }
}

tag_constant!(PASSPORT_FIRMWARE_VERSION, 771, "passport-firmware-version");

#[derive(Clone)]
pub struct PassportFirmwareVersion(pub String);

impl CBORTagged for PassportFirmwareVersion {
    fn cbor_tags() -> Vec<Tag> {
        vec![PASSPORT_FIRMWARE_VERSION]
    }
}

impl CBORTaggedEncodable for PassportFirmwareVersion {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::from(self.0.clone())
    }
}

impl TryFrom<CBOR> for PassportFirmwareVersion {
    type Error = Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(value)
    }
}

impl CBORTaggedDecodable for PassportFirmwareVersion {
    fn from_untagged_cbor(cbor: CBOR) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let version = cbor.try_into_text()?;
        Ok(PassportFirmwareVersion(version))
    }
}

tag_constant!(PASSPORT_SERIAL, 761, "passport-serial");

#[derive(Clone)]
pub struct PassportSerial(pub String);

impl CBORTagged for PassportSerial {
    fn cbor_tags() -> Vec<Tag> {
        vec![PASSPORT_SERIAL]
    }
}

impl CBORTaggedEncodable for PassportSerial {
    fn untagged_cbor(&self) -> CBOR {
        CBOR::from(self.0.clone())
    }
}

impl TryFrom<CBOR> for PassportSerial {
    type Error = Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(value)
    }
}

impl CBORTaggedDecodable for PassportSerial {
    fn from_untagged_cbor(cbor: CBOR) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let serial = cbor.try_into_text()?;
        Ok(PassportSerial(serial))
    }
}
