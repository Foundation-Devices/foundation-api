use bc_components::{
    MLDSAPublicKey, MLKEMCiphertext, MLKEMPublicKey, SigningPublicKey, SymmetricKey, XID,
};
use rkyv::{Archive, Serialize};

use super::{PairRequestBody, PairRequestRecord};
use crate::{
    engine::QlCrypto,
    identity::QlIdentity,
    wire::{
        access_value, deserialize_value, encode_value,
        encrypted_message::{ArchivedEncryptedMessage, EncryptedMessage, NONCE_SIZE},
        ensure_not_expired, AsWireMlDsaPublicKey, AsWireMlKemCiphertext, AsWireMlKemPublicKey,
        ControlMeta, QlHeader, QlPayload, QlRecord,
    },
    QlError,
};

#[derive(Archive, Serialize)]
struct PairingAad {
    header: QlHeader,
    #[rkyv(with = AsWireMlKemCiphertext)]
    kem_ct: MLKEMCiphertext,
}

#[derive(Archive, Serialize)]
struct PairingProofData {
    aad: Vec<u8>,
    meta: ControlMeta,
    #[rkyv(with = AsWireMlDsaPublicKey)]
    signing_pub_key: MLDSAPublicKey,
    #[rkyv(with = AsWireMlKemPublicKey)]
    encapsulation_pub_key: MLKEMPublicKey,
}

pub fn build_pair_request(
    identity: &QlIdentity,
    crypto: &impl QlCrypto,
    recipient: XID,
    recipient_encapsulation_key: &MLKEMPublicKey,
    meta: ControlMeta,
) -> Result<QlRecord, QlError> {
    let (session_key, kem_ct) = recipient_encapsulation_key.encapsulate_new_shared_secret();
    let header = QlHeader {
        sender: identity.xid,
        recipient,
    };
    let signing_pub_key = identity.signing_public_key.clone();
    let sender_encapsulation_key = identity.encapsulation_public_key.clone();
    let proof_data = pairing_proof_data(
        &header,
        &kem_ct,
        &meta,
        &signing_pub_key,
        &sender_encapsulation_key,
    );
    let proof = identity.signing_private_key.sign(&proof_data);
    let body = PairRequestBody {
        meta,
        signing_pub_key,
        encapsulation_pub_key: sender_encapsulation_key,
        proof,
    };
    let body_bytes = encode_value(&body);
    let aad = pairing_aad(&header, &kem_ct);
    let mut nonce = [0u8; NONCE_SIZE];
    crypto.fill_random_bytes(&mut nonce);
    let encrypted = EncryptedMessage::encrypt(&session_key, body_bytes, &aad, nonce);
    Ok(QlRecord {
        header,
        payload: QlPayload::Pair(PairRequestRecord { kem_ct, encrypted }),
    })
}

pub fn decrypt_pair_request(
    identity: &QlIdentity,
    header: &QlHeader,
    request: &mut super::ArchivedPairRequestRecord,
) -> Result<PairRequestBody, QlError> {
    let kem_ct = MLKEMCiphertext::try_from(&request.kem_ct)?;
    let aad = pairing_aad(header, &kem_ct);
    let session_key = identity
        .encapsulation_private_key
        .decapsulate_shared_secret(&kem_ct)
        .map_err(|_| QlError::InvalidPayload)?;
    let decrypted = decrypt_body(&session_key, &mut request.encrypted, &aad)?;
    ensure_not_expired(decrypted.meta.valid_until)?;
    if XID::new(SigningPublicKey::MLDSA(decrypted.signing_pub_key.clone())) != header.sender {
        return Err(QlError::InvalidPayload);
    }
    let proof_data = pairing_proof_data(
        header,
        &kem_ct,
        &decrypted.meta,
        &decrypted.signing_pub_key,
        &decrypted.encapsulation_pub_key,
    );
    if decrypted
        .signing_pub_key
        .verify(&decrypted.proof, &proof_data)
        .unwrap_or(false)
    {
        Ok(decrypted)
    } else {
        Err(QlError::InvalidSignature)
    }
}

fn pairing_proof_data(
    header: &QlHeader,
    kem_ct: &MLKEMCiphertext,
    meta: &ControlMeta,
    signing_pub_key: &MLDSAPublicKey,
    encapsulation_pub_key: &MLKEMPublicKey,
) -> Vec<u8> {
    encode_value(&PairingProofData {
        aad: pairing_aad(header, kem_ct),
        meta: *meta,
        signing_pub_key: signing_pub_key.clone(),
        encapsulation_pub_key: encapsulation_pub_key.clone(),
    })
}

fn decrypt_body(
    key: &SymmetricKey,
    encrypted: &mut ArchivedEncryptedMessage,
    aad: &[u8],
) -> Result<PairRequestBody, QlError> {
    let plaintext = encrypted.decrypt(key, aad)?;
    let body = access_value::<super::ArchivedPairRequestBody>(plaintext)?;
    deserialize_value(body)
}

pub(crate) fn pairing_aad(header: &QlHeader, kem_ct: &MLKEMCiphertext) -> Vec<u8> {
    encode_value(&PairingAad {
        header: header.clone(),
        kem_ct: kem_ct.clone(),
    })
}
