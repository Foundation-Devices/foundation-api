use {
    crate::api::passport::{PassportFirmwareVersion, PassportModel, PassportSerial},
    anyhow::Error,
    bc_components::tag_constant,
    dcbor::{CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Tag, CBOR},
    paste::paste,
};

tag_constant!(PASSPORT_PAIRING_RESPONSE, 701, "passport-pairing-response");

pub struct PairingResponse {
    pub passport_model: PassportModel,
    pub passport_firmware_version: PassportFirmwareVersion,
    pub passport_serial: PassportSerial,
}

impl CBORTagged for PairingResponse {
    fn cbor_tags() -> Vec<Tag> {
        vec![PASSPORT_PAIRING_RESPONSE]
    }
}

impl CBORTaggedEncodable for PairingResponse {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = dcbor::Map::new();
        map.insert(1, self.passport_model.tagged_cbor());
        map.insert(2, self.passport_firmware_version.tagged_cbor());
        map.insert(3, self.passport_serial.tagged_cbor());
        map.into()
    }
}

impl TryFrom<CBOR> for PairingResponse {
    type Error = Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        Self::from_tagged_cbor(value)
    }
}

impl CBORTaggedDecodable for PairingResponse {
    fn from_untagged_cbor(cbor: CBOR) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let map = cbor.try_into_map()?;
        let passport_model: PassportModel = map.extract::<i32, CBOR>(1)?.try_into()?;
        let passport_firmware_version: PassportFirmwareVersion =
            map.extract::<i32, CBOR>(2)?.try_into()?;
        let passport_serial: PassportSerial = map.extract::<i32, CBOR>(3)?.try_into()?;

        Ok(PairingResponse {
            passport_model,
            passport_firmware_version,
            passport_serial,
        })
    }
}
