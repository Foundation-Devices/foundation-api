use bc_components::MLDSAPublicKey;
use rkyv::{Archive, Serialize};

use super::UnpairRecord;
use crate::{
    platform::QlCrypto,
    wire::{
        deserialize_value, encode_value, mldsa_signature_from_archived, now_secs, ArchivedQlHeader,
        QlHeader, QlPayload, QlRecord,
    },
    MessageId, QlError,
};

#[derive(Archive, Serialize)]
struct UnpairProofData {
    domain: Vec<u8>,
    header: QlHeader,
    message_id: MessageId,
    valid_until: u64,
}

pub fn build_unpair_record(
    platform: &impl QlCrypto,
    header: QlHeader,
    message_id: MessageId,
    valid_until: u64,
) -> QlRecord {
    let signature =
        platform
            .signing_private_key()
            .sign(&unpair_proof_data(&header, message_id, valid_until));
    QlRecord {
        header,
        payload: QlPayload::Unpair(UnpairRecord {
            message_id,
            valid_until,
            signature,
        }),
    }
}

pub fn verify_unpair_record(
    header: &ArchivedQlHeader,
    record: &super::ArchivedUnpairRecord,
    signing_key: &MLDSAPublicKey,
) -> Result<(), QlError> {
    let header = deserialize_value(header)?;
    let message_id = (&record.message_id).into();
    let valid_until = record.valid_until.to_native();
    let signature = mldsa_signature_from_archived(&record.signature)?;
    if now_secs() > valid_until {
        return Err(QlError::InvalidPayload);
    }
    let proof_data = unpair_proof_data(&header, message_id, valid_until);
    if signing_key.verify(&signature, &proof_data).unwrap_or(false) {
        Ok(())
    } else {
        Err(QlError::InvalidSignature)
    }
}

fn unpair_proof_data(header: &QlHeader, message_id: MessageId, valid_until: u64) -> Vec<u8> {
    encode_value(&UnpairProofData {
        domain: b"ql-unpair-v1".to_vec(),
        header: header.clone(),
        message_id,
        valid_until,
    })
}
