use bc_components::{
    AuthenticationTag, EncryptedMessage, MLDSAPublicKey, MLDSASignature, MLKEMCiphertext,
    MLKEMPublicKey, Nonce, MLDSA, MLKEM, XID,
};
use rkyv::{
    rancor::{Fallible, Source},
    with::{ArchiveWith, DeserializeWith, SerializeWith},
    Archive, Archived, Deserialize, Place, Resolver, Serialize,
};

use crate::QlError;

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
            $wire: TryInto<$external, Error = QlError>,
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

#[derive(
    Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub(crate) struct WireXid(pub(crate) [u8; XID::XID_SIZE]);

impl From<&XID> for WireXid {
    fn from(value: &XID) -> Self {
        Self(*value.data())
    }
}

impl TryFrom<WireXid> for XID {
    type Error = QlError;

    fn try_from(value: WireXid) -> Result<Self, Self::Error> {
        Ok(XID::from_data(value.0))
    }
}

pub(crate) fn xid_from_archived(value: &ArchivedWireXid) -> XID {
    XID::from_data(value.0)
}

impl_wire_wrapper!(AsWireXid, XID, WireXid);

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WireNonce(pub(crate) [u8; Nonce::NONCE_SIZE]);

impl From<&Nonce> for WireNonce {
    fn from(value: &Nonce) -> Self {
        Self(*value.data())
    }
}

impl TryFrom<WireNonce> for Nonce {
    type Error = QlError;

    fn try_from(value: WireNonce) -> Result<Self, Self::Error> {
        Ok(Nonce::from_data(value.0))
    }
}

pub(crate) fn nonce_from_archived(value: &ArchivedWireNonce) -> Nonce {
    Nonce::from_data(value.0)
}

impl_wire_wrapper!(AsWireNonce, Nonce, WireNonce);

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WireAuthenticationTag(
    pub(crate) [u8; AuthenticationTag::AUTHENTICATION_TAG_SIZE],
);

impl From<&AuthenticationTag> for WireAuthenticationTag {
    fn from(value: &AuthenticationTag) -> Self {
        Self(*value.data())
    }
}

impl TryFrom<WireAuthenticationTag> for AuthenticationTag {
    type Error = QlError;

    fn try_from(value: WireAuthenticationTag) -> Result<Self, Self::Error> {
        Ok(AuthenticationTag::from_data(value.0))
    }
}

pub(crate) fn authentication_tag_from_archived(
    value: &ArchivedWireAuthenticationTag,
) -> AuthenticationTag {
    AuthenticationTag::from_data(value.0)
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireEncryptedMessage {
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) aad: Vec<u8>,
    pub(crate) nonce: WireNonce,
    pub(crate) auth: WireAuthenticationTag,
}

impl From<&EncryptedMessage> for WireEncryptedMessage {
    fn from(value: &EncryptedMessage) -> Self {
        Self {
            ciphertext: value.ciphertext().to_vec(),
            aad: value.aad().to_vec(),
            nonce: value.nonce().into(),
            auth: value.authentication_tag().into(),
        }
    }
}

impl TryFrom<WireEncryptedMessage> for EncryptedMessage {
    type Error = QlError;

    fn try_from(value: WireEncryptedMessage) -> Result<Self, Self::Error> {
        Ok(EncryptedMessage::new(
            value.ciphertext,
            value.aad,
            value.nonce.try_into()?,
            value.auth.try_into()?,
        ))
    }
}

pub(crate) fn encrypted_message_from_archived(
    value: &ArchivedWireEncryptedMessage,
) -> EncryptedMessage {
    EncryptedMessage::new(
        value.ciphertext.as_slice(),
        value.aad.as_slice(),
        nonce_from_archived(&value.nonce),
        authentication_tag_from_archived(&value.auth),
    )
}

impl_wire_wrapper!(
    AsWireEncryptedMessage,
    EncryptedMessage,
    WireEncryptedMessage
);

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(crate) enum WireMlDsaLevel {
    MlDsa44 = 2,
    MlDsa65 = 3,
    MlDsa87 = 5,
}

impl TryFrom<WireMlDsaLevel> for MLDSA {
    type Error = QlError;

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

pub(crate) fn mldsa_level_from_archived(value: &ArchivedWireMlDsaLevel) -> MLDSA {
    match value {
        ArchivedWireMlDsaLevel::MlDsa44 => MLDSA::MLDSA44,
        ArchivedWireMlDsaLevel::MlDsa65 => MLDSA::MLDSA65,
        ArchivedWireMlDsaLevel::MlDsa87 => MLDSA::MLDSA87,
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
    type Error = QlError;

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

pub(crate) fn mlkem_level_from_archived(value: &ArchivedWireMlKemLevel) -> MLKEM {
    match value {
        ArchivedWireMlKemLevel::MlKem512 => MLKEM::MLKEM512,
        ArchivedWireMlKemLevel::MlKem768 => MLKEM::MLKEM768,
        ArchivedWireMlKemLevel::MlKem1024 => MLKEM::MLKEM1024,
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireMlDsaPublicKey {
    pub(crate) level: WireMlDsaLevel,
    pub(crate) bytes: Vec<u8>,
}

impl TryFrom<WireMlDsaPublicKey> for MLDSAPublicKey {
    type Error = QlError;

    fn try_from(value: WireMlDsaPublicKey) -> Result<Self, Self::Error> {
        MLDSAPublicKey::from_bytes(value.level.try_into()?, &value.bytes)
            .map_err(|_| QlError::InvalidPayload)
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

impl_wire_wrapper!(AsWireMlDsaPublicKey, MLDSAPublicKey, WireMlDsaPublicKey);

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireMlDsaSignature {
    pub(crate) level: WireMlDsaLevel,
    pub(crate) bytes: Vec<u8>,
}

impl TryFrom<WireMlDsaSignature> for MLDSASignature {
    type Error = QlError;

    fn try_from(value: WireMlDsaSignature) -> Result<Self, Self::Error> {
        MLDSASignature::from_bytes(value.level.try_into()?, &value.bytes)
            .map_err(|_| QlError::InvalidPayload)
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

pub(crate) fn mldsa_signature_from_archived(
    value: &ArchivedWireMlDsaSignature,
) -> Result<MLDSASignature, QlError> {
    MLDSASignature::from_bytes(
        mldsa_level_from_archived(&value.level),
        value.bytes.as_slice(),
    )
    .map_err(|_| QlError::InvalidPayload)
}

impl_wire_wrapper!(AsWireMlDsaSignature, MLDSASignature, WireMlDsaSignature);

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireMlKemPublicKey {
    pub(crate) level: WireMlKemLevel,
    pub(crate) bytes: Vec<u8>,
}

impl TryFrom<WireMlKemPublicKey> for MLKEMPublicKey {
    type Error = QlError;

    fn try_from(value: WireMlKemPublicKey) -> Result<Self, Self::Error> {
        MLKEMPublicKey::from_bytes(value.level.try_into()?, &value.bytes)
            .map_err(|_| QlError::InvalidPayload)
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

impl_wire_wrapper!(AsWireMlKemPublicKey, MLKEMPublicKey, WireMlKemPublicKey);

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireMlKemCiphertext {
    pub(crate) level: WireMlKemLevel,
    pub(crate) bytes: Vec<u8>,
}

impl TryFrom<WireMlKemCiphertext> for MLKEMCiphertext {
    type Error = QlError;

    fn try_from(value: WireMlKemCiphertext) -> Result<Self, Self::Error> {
        MLKEMCiphertext::from_bytes(value.level.try_into()?, &value.bytes)
            .map_err(|_| QlError::InvalidPayload)
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

pub(crate) fn mlkem_ciphertext_from_archived(
    value: &ArchivedWireMlKemCiphertext,
) -> Result<MLKEMCiphertext, QlError> {
    MLKEMCiphertext::from_bytes(
        mlkem_level_from_archived(&value.level),
        value.bytes.as_slice(),
    )
    .map_err(|_| QlError::InvalidPayload)
}

impl_wire_wrapper!(AsWireMlKemCiphertext, MLKEMCiphertext, WireMlKemCiphertext);
