use std::time::Duration;

use bc_components::{
    MLDSAPublicKey, MLKEMCiphertext, MLKEMPublicKey, Nonce, SigningPublicKey, SymmetricKey, XID,
};
use rkyv::{Archive, Serialize};

use super::{PairRequestBody, PairRequestRecord};
use crate::{
    platform::QlCrypto,
    wire::{
        access_value, deserialize_value, encode_value, encrypted_message_from_archived,
        ensure_not_expired, mlkem_ciphertext_from_archived, now_secs, ArchivedQlHeader,
        AsWireMlDsaPublicKey, AsWireMlKemCiphertext, AsWireMlKemPublicKey, QlHeader, QlPayload,
        QlRecord,
    },
    MessageId, QlError,
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
    message_id: MessageId,
    valid_until: u64,
    #[rkyv(with = AsWireMlDsaPublicKey)]
    signing_pub_key: MLDSAPublicKey,
    #[rkyv(with = AsWireMlKemPublicKey)]
    encapsulation_pub_key: MLKEMPublicKey,
}

pub fn build_pair_request(
    platform: &impl QlCrypto,
    recipient: XID,
    recipient_encapsulation_key: &MLKEMPublicKey,
    message_id: MessageId,
    valid_for: Duration,
) -> Result<QlRecord, QlError> {
    let (session_key, kem_ct) = recipient_encapsulation_key.encapsulate_new_shared_secret();
    let header = QlHeader {
        sender: platform.xid(),
        recipient,
    };
    let valid_until = now_secs().saturating_add(valid_for.as_secs());
    let signing_pub_key = platform.signing_public_key().clone();
    let sender_encapsulation_key = platform.encapsulation_public_key().clone();
    let proof_data = pairing_proof_data(
        &header,
        &kem_ct,
        message_id,
        valid_until,
        &signing_pub_key,
        &sender_encapsulation_key,
    );
    let proof = platform.signing_private_key().sign(&proof_data);
    let body = PairRequestBody {
        message_id,
        valid_until,
        signing_pub_key,
        encapsulation_pub_key: sender_encapsulation_key,
        proof,
    };
    let body_bytes = encode_value(&body);
    let aad = pairing_aad(&header, &kem_ct);
    let encrypted = session_key.encrypt(body_bytes, Some(aad), None::<Nonce>);
    Ok(QlRecord {
        header,
        payload: QlPayload::Pair(PairRequestRecord { kem_ct, encrypted }),
    })
}

pub fn decrypt_pair_request(
    platform: &impl QlCrypto,
    header: &ArchivedQlHeader,
    request: &super::ArchivedPairRequestRecord,
) -> Result<PairRequestBody, QlError> {
    let header = deserialize_value(header)?;
    let kem_ct = mlkem_ciphertext_from_archived(&request.kem_ct)?;
    let encrypted = encrypted_message_from_archived(&request.encrypted);
    let session_key = platform
        .encapsulation_private_key()
        .decapsulate_shared_secret(&kem_ct)
        .map_err(|_| QlError::InvalidPayload)?;
    let aad = pairing_aad(&header, &kem_ct);
    if encrypted.aad() != aad {
        return Err(QlError::InvalidPayload);
    }
    let decrypted = decrypt_body(&session_key, &encrypted)?;
    ensure_not_expired(decrypted.valid_until)?;
    if XID::new(SigningPublicKey::MLDSA(decrypted.signing_pub_key.clone())) != header.sender {
        return Err(QlError::InvalidPayload);
    }
    let proof_data = pairing_proof_data(
        &header,
        &kem_ct,
        decrypted.message_id,
        decrypted.valid_until,
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
    message_id: MessageId,
    valid_until: u64,
    signing_pub_key: &MLDSAPublicKey,
    encapsulation_pub_key: &MLKEMPublicKey,
) -> Vec<u8> {
    encode_value(&PairingProofData {
        aad: pairing_aad(header, kem_ct),
        message_id,
        valid_until,
        signing_pub_key: signing_pub_key.clone(),
        encapsulation_pub_key: encapsulation_pub_key.clone(),
    })
}

fn decrypt_body(
    key: &SymmetricKey,
    encrypted: &bc_components::EncryptedMessage,
) -> Result<PairRequestBody, QlError> {
    let plaintext = key
        .decrypt(encrypted)
        .map_err(|_| QlError::InvalidPayload)?;
    let body = access_value::<super::ArchivedPairRequestBody>(&plaintext)?;
    deserialize_value(body)
}

fn pairing_aad(header: &QlHeader, kem_ct: &MLKEMCiphertext) -> Vec<u8> {
    encode_value(&PairingAad {
        header: header.clone(),
        kem_ct: kem_ct.clone(),
    })
}
