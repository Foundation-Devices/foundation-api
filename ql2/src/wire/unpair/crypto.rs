use bc_components::MLDSAPublicKey;
use rkyv::{Archive, Serialize};

use super::UnpairRecord;
use crate::{
    platform::QlCrypto,
    wire::{encode_value, now_secs, QlHeader, QlPayload, QlRecord},
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

pub fn verify_unpair_record<H, R>(
    header: H,
    record: R,
    signing_key: &MLDSAPublicKey,
) -> Result<(), QlError>
where
    H: TryInto<QlHeader, Error = QlError>,
    R: TryInto<UnpairRecord, Error = QlError>,
{
    let header = header.try_into()?;
    let record = record.try_into()?;
    if now_secs() > record.valid_until {
        return Err(QlError::InvalidPayload);
    }
    let proof_data = unpair_proof_data(&header, record.message_id, record.valid_until);
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
    encode_value(&UnpairProofData {
        domain: b"ql-unpair-v1".to_vec(),
        header: header.clone(),
        message_id,
        valid_until,
    })
}
