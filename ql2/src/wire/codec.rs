use bc_components::{
    AuthenticationTag, EncryptedMessage, MLDSAPublicKey, MLDSASignature, MLKEMCiphertext,
    MLKEMPublicKey, Nonce, MLDSA, MLKEM, XID,
};
use rkyv::{
    rancor::Fallible,
    with::{ArchiveWith, SerializeWith},
    Archive, Archived, Place, Resolver, Serialize,
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
    };
}

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct WireXid(pub(crate) [u8; XID::XID_SIZE]);

impl From<&XID> for WireXid {
    fn from(value: &XID) -> Self {
        Self(*value.data())
    }
}

pub(crate) fn xid_from_archived(value: &ArchivedWireXid) -> XID {
    XID::from_data(value.0)
}

impl_wire_wrapper!(AsWireXid, XID, WireXid);

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WireNonce(pub(crate) [u8; Nonce::NONCE_SIZE]);

impl From<&Nonce> for WireNonce {
    fn from(value: &Nonce) -> Self {
        Self(*value.data())
    }
}

pub(crate) fn nonce_from_archived(value: &ArchivedWireNonce) -> Nonce {
    Nonce::from_data(value.0)
}

impl_wire_wrapper!(AsWireNonce, Nonce, WireNonce);

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WireAuthenticationTag(
    pub(crate) [u8; AuthenticationTag::AUTHENTICATION_TAG_SIZE],
);

impl From<&AuthenticationTag> for WireAuthenticationTag {
    fn from(value: &AuthenticationTag) -> Self {
        Self(*value.data())
    }
}

pub(crate) fn authentication_tag_from_archived(
    value: &ArchivedWireAuthenticationTag,
) -> AuthenticationTag {
    AuthenticationTag::from_data(value.0)
}

#[derive(Archive, Serialize, Debug, Clone, PartialEq, Eq)]
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

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(crate) enum WireMlDsaLevel {
    MlDsa44 = 2,
    MlDsa65 = 3,
    MlDsa87 = 5,
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

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(crate) enum WireMlKemLevel {
    MlKem512 = 1,
    MlKem768 = 2,
    MlKem1024 = 3,
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

#[derive(Archive, Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireMlDsaPublicKey {
    pub(crate) level: WireMlDsaLevel,
    pub(crate) bytes: Vec<u8>,
}

impl From<&MLDSAPublicKey> for WireMlDsaPublicKey {
    fn from(value: &MLDSAPublicKey) -> Self {
        Self {
            level: value.level().into(),
            bytes: value.as_bytes().to_vec(),
        }
    }
}

pub(crate) fn mldsa_public_key_from_archived(
    value: &ArchivedWireMlDsaPublicKey,
) -> Result<MLDSAPublicKey, QlError> {
    MLDSAPublicKey::from_bytes(
        mldsa_level_from_archived(&value.level),
        value.bytes.as_slice(),
    )
    .map_err(|_| QlError::InvalidPayload)
}

impl_wire_wrapper!(AsWireMlDsaPublicKey, MLDSAPublicKey, WireMlDsaPublicKey);

#[derive(Archive, Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireMlDsaSignature {
    pub(crate) level: WireMlDsaLevel,
    pub(crate) bytes: Vec<u8>,
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

#[derive(Archive, Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireMlKemPublicKey {
    pub(crate) level: WireMlKemLevel,
    pub(crate) bytes: Vec<u8>,
}

impl From<&MLKEMPublicKey> for WireMlKemPublicKey {
    fn from(value: &MLKEMPublicKey) -> Self {
        Self {
            level: value.level().into(),
            bytes: value.as_bytes().to_vec(),
        }
    }
}

pub(crate) fn mlkem_public_key_from_archived(
    value: &ArchivedWireMlKemPublicKey,
) -> Result<MLKEMPublicKey, QlError> {
    MLKEMPublicKey::from_bytes(
        mlkem_level_from_archived(&value.level),
        value.bytes.as_slice(),
    )
    .map_err(|_| QlError::InvalidPayload)
}

impl_wire_wrapper!(AsWireMlKemPublicKey, MLKEMPublicKey, WireMlKemPublicKey);

#[derive(Archive, Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireMlKemCiphertext {
    pub(crate) level: WireMlKemLevel,
    pub(crate) bytes: Vec<u8>,
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
