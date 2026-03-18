use bc_components::{MLDSAPublicKey, MLDSASignature};
use rkyv::{Archive, Serialize};

use super::UnpairRecord;
use crate::{
    identity::QlIdentity,
    wire::{encode_value, ensure_not_expired, ControlMeta, QlHeader, QlPayload, QlRecord},
    QlError,
};

#[derive(Archive, Serialize)]
struct UnpairProofData {
    domain: Vec<u8>,
    header: QlHeader,
    meta: ControlMeta,
}

pub fn build_unpair_record(identity: &QlIdentity, header: QlHeader, meta: ControlMeta) -> QlRecord {
    let signature = identity
        .signing_private_key
        .sign(unpair_proof_data(&header, &meta));
    QlRecord {
        header,
        payload: QlPayload::Unpair(UnpairRecord { meta, signature }),
    }
}

pub fn verify_unpair_record(
    header: &QlHeader,
    record: &super::ArchivedUnpairRecord,
    signing_key: &MLDSAPublicKey,
) -> Result<(), QlError> {
    let meta: ControlMeta = (&record.meta).into();
    let signature = MLDSASignature::try_from(&record.signature)?;
    ensure_not_expired(meta.valid_until)?;
    let proof_data = unpair_proof_data(header, &meta);
    if signing_key.verify(&signature, &proof_data).unwrap_or(false) {
        Ok(())
    } else {
        Err(QlError::InvalidSignature)
    }
}

fn unpair_proof_data(header: &QlHeader, meta: &ControlMeta) -> Vec<u8> {
    encode_value(&UnpairProofData {
        domain: b"ql-unpair-v1".to_vec(),
        header: header.clone(),
        meta: *meta,
    })
}
