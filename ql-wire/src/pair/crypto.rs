use super::{PairRequestBody, PairRequestRecord};
use crate::{
    access_value, deserialize_value, encode_value,
    encrypted_message::{ArchivedEncryptedMessage, EncryptedMessage},
    ensure_not_expired, pq::ML_KEM_SUITE_TAG, ControlMeta, MlDsaPublicKey, MlKemCiphertext,
    MlKemPublicKey, Nonce, QlCrypto, QlHeader, QlIdentity, QlPayload, QlRecord, SessionKey,
    WireError, XID,
};

pub fn build_pair_request(
    crypto: &impl QlCrypto,
    identity: &QlIdentity,
    recipient: XID,
    recipient_encapsulation_key: &MlKemPublicKey,
    meta: ControlMeta,
) -> Result<QlRecord, WireError> {
    let (session_key, kem_ct) = recipient_encapsulation_key.encapsulate_new_shared_secret(crypto)?;
    let header = QlHeader {
        sender: identity.xid,
        recipient,
    };
    let signing_pub_key = identity.signing_public_key.clone();
    let sender_encapsulation_key = identity.encapsulation_public_key.clone();
    let proof_data = hash_pairing_proof_data(
        crypto,
        &header,
        &kem_ct,
        &meta,
        identity.xid,
        &signing_pub_key,
        &sender_encapsulation_key,
    );
    let proof = identity.signing_private_key.sign(crypto, &proof_data)?;
    let body = PairRequestBody {
        meta,
        xid: identity.xid,
        signing_pub_key,
        encapsulation_pub_key: sender_encapsulation_key,
        proof,
    };
    let body_bytes = encode_value(&body);
    let aad = pairing_aad(&header, &kem_ct);
    let mut nonce_bytes = [0u8; Nonce::NONCE_SIZE];
    crypto.fill_random_bytes(&mut nonce_bytes);
    let encrypted =
        EncryptedMessage::encrypt(crypto, &session_key, body_bytes, &aad, Nonce(nonce_bytes))?;
    Ok(QlRecord {
        header,
        payload: QlPayload::Pair(PairRequestRecord { kem_ct, encrypted }),
    })
}

pub fn decrypt_pair_request(
    crypto: &impl QlCrypto,
    identity: &QlIdentity,
    header: &QlHeader,
    request: &mut super::ArchivedPairRequestRecord,
    now_seconds: u64,
) -> Result<PairRequestBody, WireError> {
    let kem_ct = deserialize_value(&request.kem_ct)?;
    let aad = pairing_aad(header, &kem_ct);
    let session_key = identity
        .encapsulation_private_key
        .decapsulate_shared_secret(&kem_ct)?;
    let decrypted = decrypt_body(crypto, &session_key, &mut request.encrypted, &aad)?;
    ensure_not_expired(&decrypted.meta, now_seconds)?;
    if decrypted.xid != header.sender {
        return Err(WireError::InvalidPayload);
    }
    let proof_data = hash_pairing_proof_data(
        crypto,
        header,
        &kem_ct,
        &decrypted.meta,
        decrypted.xid,
        &decrypted.signing_pub_key,
        &decrypted.encapsulation_pub_key,
    );
    if decrypted.signing_pub_key.verify(&decrypted.proof, &proof_data) {
        Ok(decrypted)
    } else {
        Err(WireError::InvalidSignature)
    }
}

fn hash_pairing_proof_data(
    crypto: &impl QlCrypto,
    header: &QlHeader,
    kem_ct: &MlKemCiphertext,
    meta: &ControlMeta,
    xid: XID,
    signing_pub_key: &MlDsaPublicKey,
    encapsulation_pub_key: &MlKemPublicKey,
) -> [u8; 32] {
    let aad = pairing_aad(header, kem_ct);
    let control_id = meta.control_id.0.to_le_bytes();
    let valid_until = meta.valid_until.to_le_bytes();
    crypto.hash(&[
        b"ql-wire:pair-proof:v1",
        b"aad",
        &aad,
        b"control-id",
        &control_id,
        b"valid-until",
        &valid_until,
        b"xid",
        &xid.0,
        b"signing-pub-key",
        signing_pub_key.as_bytes(),
        b"encapsulation-pub-key-suite",
        ML_KEM_SUITE_TAG,
        b"encapsulation-pub-key",
        encapsulation_pub_key.as_bytes(),
    ])
}

fn decrypt_body(
    crypto: &impl QlCrypto,
    key: &SessionKey,
    encrypted: &mut ArchivedEncryptedMessage,
    aad: &[u8],
) -> Result<PairRequestBody, WireError> {
    let plaintext = encrypted.decrypt(crypto, key, aad)?;
    let body = access_value::<super::ArchivedPairRequestBody>(plaintext)?;
    deserialize_value(body)
}

pub(crate) fn pairing_aad(header: &QlHeader, kem_ct: &MlKemCiphertext) -> Vec<u8> {
    let mut aad = Vec::new();
    append_field(&mut aad, b"domain", b"ql-wire:pair-aad:v1");
    append_field(&mut aad, b"sender", &header.sender.0);
    append_field(&mut aad, b"recipient", &header.recipient.0);
    append_field(&mut aad, b"kem-suite", ML_KEM_SUITE_TAG);
    append_field(&mut aad, b"kem-ct", kem_ct.as_bytes());
    aad
}

fn append_field(out: &mut Vec<u8>, label: &[u8], value: &[u8]) {
    append_framed_bytes(out, label);
    append_framed_bytes(out, value);
}

fn append_framed_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u64::try_from(value.len()).unwrap().to_le_bytes());
    out.extend_from_slice(value);
}
