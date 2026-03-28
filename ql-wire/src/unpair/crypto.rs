use super::Unpair;
use crate::{
    ControlMeta, MlDsaPublicKey, QlCrypto, QlHeader, QlIdentity, QlPayload, QlRecord, WireError,
    XID,
};

pub fn build_unpair(
    crypto: &impl QlCrypto,
    identity: &QlIdentity,
    recipient: XID,
    meta: ControlMeta,
) -> QlRecord {
    let header = QlHeader {
        sender: identity.xid,
        recipient,
    };
    let signature = identity
        .signing_private_key
        .sign(crypto, &hash_unpair_signature_data(crypto, &header, &meta));
    QlRecord {
        header,
        payload: QlPayload::Unpair(Unpair { meta, signature }),
    }
}

pub fn verify_unpair(
    crypto: &impl QlCrypto,
    header: &QlHeader,
    signer: &MlDsaPublicKey,
    unpair: &Unpair,
    now_seconds: u64,
) -> Result<(), WireError> {
    unpair.meta.ensure_not_expired(now_seconds)?;
    if signer.verify_bytes(
        unpair.signature.as_bytes(),
        &hash_unpair_signature_data(crypto, header, &unpair.meta),
    ) {
        Ok(())
    } else {
        Err(WireError::InvalidSignature)
    }
}

fn hash_unpair_signature_data(
    crypto: &impl QlCrypto,
    header: &QlHeader,
    meta: &ControlMeta,
) -> [u8; 32] {
    let aad = header.aad();
    let control_id = meta.control_id.0.to_le_bytes();
    let valid_until = meta.valid_until.to_le_bytes();
    crypto.hash(&[
        b"ql-wire:unpair:v1",
        b"aad",
        &aad,
        b"control-id",
        &control_id,
        b"valid-until",
        &valid_until,
    ])
}
