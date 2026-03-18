use bc_components::{
    MLDSAPublicKey, MLDSASignature, MLKEMCiphertext, MLKEMPublicKey, MLDSA, MLKEM,
};
use rkyv::{
    rancor::{Fallible, Source},
    with::{ArchiveWith, DeserializeWith, SerializeWith},
    Archive, Archived, Deserialize, Place, Resolver, Serialize,
};

use crate::WireError;

macro_rules! impl_wire_wrapper {
    ($marker:ident, $external:ty, $wire:ty) => {
        pub(crate) struct $marker;

        impl ArchiveWith<$external> for $marker {
            type Archived = Archived<$wire>;
            type Resolver = Resolver<$wire>;

            fn resolve_with(
                field: &$external,
                resolver: Self::Resolver,
                out: Place<Self::Archived>,
            ) {
                <$wire>::from(field).resolve(resolver, out);
            }
        }

        impl<S> SerializeWith<$external, S> for $marker
        where
            S: Fallible + ?Sized,
            $wire: Serialize<S>,
        {
            fn serialize_with(
                field: &$external,
                serializer: &mut S,
            ) -> Result<Self::Resolver, S::Error> {
                <$wire>::from(field).serialize(serializer)
            }
        }

        impl<D> DeserializeWith<Archived<$wire>, $external, D> for $marker
        where
            D: Fallible + ?Sized,
            D::Error: Source,
            Archived<$wire>: Deserialize<$wire, D>,
            $wire: TryInto<$external, Error = WireError>,
        {
            fn deserialize_with(
                field: &Archived<$wire>,
                deserializer: &mut D,
            ) -> Result<$external, D::Error> {
                field
                    .deserialize(deserializer)?
                    .try_into()
                    .map_err(D::Error::new)
            }
        }
    };
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(crate) enum WireMlDsaLevel {
    MlDsa44 = 2,
    MlDsa65 = 3,
    MlDsa87 = 5,
}

impl TryFrom<WireMlDsaLevel> for MLDSA {
    type Error = WireError;

    fn try_from(value: WireMlDsaLevel) -> Result<Self, Self::Error> {
        Ok(match value {
            WireMlDsaLevel::MlDsa44 => MLDSA::MLDSA44,
            WireMlDsaLevel::MlDsa65 => MLDSA::MLDSA65,
            WireMlDsaLevel::MlDsa87 => MLDSA::MLDSA87,
        })
    }
}

impl From<MLDSA> for WireMlDsaLevel {
    fn from(value: MLDSA) -> Self {
        match value {
            MLDSA::MLDSA44 => Self::MlDsa44,
            MLDSA::MLDSA65 => Self::MlDsa65,
            MLDSA::MLDSA87 => Self::MlDsa87,
        }
    }
}

impl From<&ArchivedWireMlDsaLevel> for MLDSA {
    fn from(value: &ArchivedWireMlDsaLevel) -> Self {
        match value {
            ArchivedWireMlDsaLevel::MlDsa44 => MLDSA::MLDSA44,
            ArchivedWireMlDsaLevel::MlDsa65 => MLDSA::MLDSA65,
            ArchivedWireMlDsaLevel::MlDsa87 => MLDSA::MLDSA87,
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(crate) enum WireMlKemLevel {
    MlKem512 = 1,
    MlKem768 = 2,
    MlKem1024 = 3,
}

impl TryFrom<WireMlKemLevel> for MLKEM {
    type Error = WireError;

    fn try_from(value: WireMlKemLevel) -> Result<Self, Self::Error> {
        Ok(match value {
            WireMlKemLevel::MlKem512 => MLKEM::MLKEM512,
            WireMlKemLevel::MlKem768 => MLKEM::MLKEM768,
            WireMlKemLevel::MlKem1024 => MLKEM::MLKEM1024,
        })
    }
}

impl From<MLKEM> for WireMlKemLevel {
    fn from(value: MLKEM) -> Self {
        match value {
            MLKEM::MLKEM512 => Self::MlKem512,
            MLKEM::MLKEM768 => Self::MlKem768,
            MLKEM::MLKEM1024 => Self::MlKem1024,
        }
    }
}

impl From<&ArchivedWireMlKemLevel> for MLKEM {
    fn from(value: &ArchivedWireMlKemLevel) -> Self {
        match value {
            ArchivedWireMlKemLevel::MlKem512 => MLKEM::MLKEM512,
            ArchivedWireMlKemLevel::MlKem768 => MLKEM::MLKEM768,
            ArchivedWireMlKemLevel::MlKem1024 => MLKEM::MLKEM1024,
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireMlDsaPublicKey {
    pub(crate) level: WireMlDsaLevel,
    pub(crate) bytes: Vec<u8>,
}

impl TryFrom<WireMlDsaPublicKey> for MLDSAPublicKey {
    type Error = WireError;

    fn try_from(value: WireMlDsaPublicKey) -> Result<Self, Self::Error> {
        MLDSAPublicKey::from_bytes(value.level.try_into()?, &value.bytes)
            .map_err(|_| WireError::InvalidPayload)
    }
}

impl From<&MLDSAPublicKey> for WireMlDsaPublicKey {
    fn from(value: &MLDSAPublicKey) -> Self {
        Self {
            level: value.level().into(),
            bytes: value.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<&ArchivedWireMlDsaPublicKey> for MLDSAPublicKey {
    type Error = WireError;

    fn try_from(value: &ArchivedWireMlDsaPublicKey) -> Result<Self, Self::Error> {
        MLDSAPublicKey::from_bytes((&value.level).into(), value.bytes.as_slice())
            .map_err(|_| WireError::InvalidPayload)
    }
}

impl_wire_wrapper!(AsWireMlDsaPublicKey, MLDSAPublicKey, WireMlDsaPublicKey);

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireMlDsaSignature {
    pub(crate) level: WireMlDsaLevel,
    pub(crate) bytes: Vec<u8>,
}

impl TryFrom<WireMlDsaSignature> for MLDSASignature {
    type Error = WireError;

    fn try_from(value: WireMlDsaSignature) -> Result<Self, Self::Error> {
        MLDSASignature::from_bytes(value.level.try_into()?, &value.bytes)
            .map_err(|_| WireError::InvalidPayload)
    }
}

impl From<&MLDSASignature> for WireMlDsaSignature {
    fn from(value: &MLDSASignature) -> Self {
        Self {
            level: value.level().into(),
            bytes: value.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<&ArchivedWireMlDsaSignature> for MLDSASignature {
    type Error = WireError;

    fn try_from(value: &ArchivedWireMlDsaSignature) -> Result<Self, Self::Error> {
        MLDSASignature::from_bytes((&value.level).into(), value.bytes.as_slice())
            .map_err(|_| WireError::InvalidPayload)
    }
}

impl_wire_wrapper!(AsWireMlDsaSignature, MLDSASignature, WireMlDsaSignature);

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireMlKemPublicKey {
    pub(crate) level: WireMlKemLevel,
    pub(crate) bytes: Vec<u8>,
}

impl TryFrom<WireMlKemPublicKey> for MLKEMPublicKey {
    type Error = WireError;

    fn try_from(value: WireMlKemPublicKey) -> Result<Self, Self::Error> {
        MLKEMPublicKey::from_bytes(value.level.try_into()?, &value.bytes)
            .map_err(|_| WireError::InvalidPayload)
    }
}

impl From<&MLKEMPublicKey> for WireMlKemPublicKey {
    fn from(value: &MLKEMPublicKey) -> Self {
        Self {
            level: value.level().into(),
            bytes: value.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<&ArchivedWireMlKemPublicKey> for MLKEMPublicKey {
    type Error = WireError;

    fn try_from(value: &ArchivedWireMlKemPublicKey) -> Result<Self, Self::Error> {
        MLKEMPublicKey::from_bytes((&value.level).into(), value.bytes.as_slice())
            .map_err(|_| WireError::InvalidPayload)
    }
}

impl_wire_wrapper!(AsWireMlKemPublicKey, MLKEMPublicKey, WireMlKemPublicKey);

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireMlKemCiphertext {
    pub(crate) level: WireMlKemLevel,
    pub(crate) bytes: Vec<u8>,
}

impl TryFrom<WireMlKemCiphertext> for MLKEMCiphertext {
    type Error = WireError;

    fn try_from(value: WireMlKemCiphertext) -> Result<Self, Self::Error> {
        MLKEMCiphertext::from_bytes(value.level.try_into()?, &value.bytes)
            .map_err(|_| WireError::InvalidPayload)
    }
}

impl From<&MLKEMCiphertext> for WireMlKemCiphertext {
    fn from(value: &MLKEMCiphertext) -> Self {
        Self {
            level: value.level().into(),
            bytes: value.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<&ArchivedWireMlKemCiphertext> for MLKEMCiphertext {
    type Error = WireError;

    fn try_from(value: &ArchivedWireMlKemCiphertext) -> Result<Self, Self::Error> {
        MLKEMCiphertext::from_bytes((&value.level).into(), value.bytes.as_slice())
            .map_err(|_| WireError::InvalidPayload)
    }
}

impl_wire_wrapper!(AsWireMlKemCiphertext, MLKEMCiphertext, WireMlKemCiphertext);
