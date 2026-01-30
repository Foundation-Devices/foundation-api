use bc_components::{EncapsulationCiphertext, EncapsulationPublicKey, Signature, SigningPublicKey};
use dcbor::CBOR;

use super::take_fields;
use crate::MessageId;

#[derive(Debug, Clone, PartialEq)]
pub struct PairingRequest {
    pub kem_ct: EncapsulationCiphertext,
    pub encrypted: bc_components::EncryptedMessage,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PairingPayload {
    pub message_id: MessageId,
    pub valid_until: u64,
    pub signing_pub_key: SigningPublicKey,
    pub encapsulation_pub_key: EncapsulationPublicKey,
    pub proof: Signature,
}

impl From<PairingRequest> for CBOR {
    fn from(value: PairingRequest) -> Self {
        CBOR::from(vec![CBOR::from(value.kem_ct), CBOR::from(value.encrypted)])
    }
}

impl TryFrom<CBOR> for PairingRequest {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        let mut iter = array.into_iter();
        let [kem_ct_cbor, encrypted_cbor] = take_fields(&mut iter)?;
        Ok(Self {
            kem_ct: kem_ct_cbor.try_into()?,
            encrypted: encrypted_cbor.try_into()?,
        })
    }
}

impl From<PairingPayload> for CBOR {
    fn from(value: PairingPayload) -> Self {
        CBOR::from(vec![
            CBOR::from(value.message_id),
            CBOR::from(value.valid_until),
            CBOR::from(value.signing_pub_key),
            CBOR::from(value.encapsulation_pub_key),
            CBOR::from(value.proof),
        ])
    }
}

impl TryFrom<CBOR> for PairingPayload {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let iter = value.try_into_array()?.into_iter();
        let [message_id, valid_until, signing_pub_key, encapsulation_pub_key, proof] =
            take_fields(iter)?;
        Ok(Self {
            message_id: message_id.try_into()?,
            valid_until: valid_until.try_into()?,
            signing_pub_key: signing_pub_key.try_into()?,
            encapsulation_pub_key: encapsulation_pub_key.try_into()?,
            proof: proof.try_into()?,
        })
    }
}
