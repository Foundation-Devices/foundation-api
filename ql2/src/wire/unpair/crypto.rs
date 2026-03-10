use bc_components::MLDSAPublicKey;
use dcbor::CBOR;

use super::UnpairRecord;
use crate::{
    platform::QlCrypto,
    wire::{now_secs, QlHeader, QlPayload, QlRecord},
    MessageId, QlError,
};

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
    header: &QlHeader,
    record: &UnpairRecord,
    signing_key: &MLDSAPublicKey,
) -> Result<(), QlError> {
    if now_secs() > record.valid_until {
        return Err(QlError::InvalidPayload);
    }
    let proof_data = unpair_proof_data(header, record.message_id, record.valid_until);
    if signing_key
        .verify(&record.signature, &proof_data)
        .unwrap_or(false)
    {
        Ok(())
    } else {
        Err(QlError::InvalidSignature)
    }
}

fn unpair_proof_data(header: &QlHeader, message_id: MessageId, valid_until: u64) -> Vec<u8> {
    CBOR::from(vec![
        CBOR::from("ql-unpair-v1"),
        CBOR::from(header.clone()),
        CBOR::from(message_id),
        CBOR::from(valid_until),
    ])
    .to_cbor_data()
}
