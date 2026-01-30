use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bc_components::{EncapsulationPublicKey, Nonce, SigningPublicKey, SymmetricKey, Verifier, XID};
use dcbor::CBOR;

use crate::{
    platform::{QlPlatform, QlPlatformExt},
    wire::{
        pairing::{PairingPayload, PairingRequest},
        QlHeader, QlMessage, QlPayload,
    },
    MessageId, QlError,
};

pub fn build_pairing_message(
    platform: &impl QlPlatform,
    recipient: XID,
    recipient_encapsulation_key: &EncapsulationPublicKey,
    message_id: MessageId,
    valid_for: Duration,
) -> Result<QlMessage, QlError> {
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
    let proof = platform
        .signer()
        .sign(&proof_data)
        .map_err(|_| QlError::InvalidPayload)?;
    let payload = PairingPayload {
        message_id,
        valid_until,
        signing_pub_key,
        encapsulation_pub_key: sender_encapsulation_key,
        proof,
    };
    let payload_bytes = CBOR::from(payload).to_cbor_data();
    let aad = pairing_aad(&header, &kem_ct);
    let encrypted = session_key.encrypt(payload_bytes, Some(aad), None::<Nonce>);
    Ok(QlMessage {
        header,
        payload: QlPayload::Pairing(PairingRequest { kem_ct, encrypted }),
    })
}

pub fn decrypt_pairing_request(
    platform: &impl QlPlatform,
    header: &QlHeader,
    request: PairingRequest,
) -> Result<PairingPayload, QlError> {
    let PairingRequest { kem_ct, encrypted } = request;
    let session_key = platform
        .encapsulation_private_key()
        .decapsulate_shared_secret(&kem_ct)
        .map_err(|_| QlError::InvalidPayload)?;
    let aad = pairing_aad(header, &kem_ct);
    if encrypted.aad() != aad {
        return Err(QlError::InvalidPayload);
    }
    let decrypted = decrypt_payload(&session_key, &encrypted)?;
    ensure_not_expired(decrypted.message_id, decrypted.valid_until)?;
    if XID::new(&decrypted.signing_pub_key) != header.sender {
        return Err(QlError::InvalidPayload);
    }
    let proof_data = pairing_proof_data(
        header,
        &kem_ct,
        decrypted.message_id,
        decrypted.valid_until,
        &decrypted.signing_pub_key,
        &decrypted.encapsulation_pub_key,
    );
    if decrypted
        .signing_pub_key
        .verify(&decrypted.proof, &proof_data)
    {
        Ok(decrypted)
    } else {
        Err(QlError::InvalidSignature)
    }
}

fn pairing_proof_data(
    header: &QlHeader,
    kem_ct: &bc_components::EncapsulationCiphertext,
    message_id: MessageId,
    valid_until: u64,
    signing_pub_key: &SigningPublicKey,
    encapsulation_pub_key: &EncapsulationPublicKey,
) -> Vec<u8> {
    CBOR::from(vec![
        CBOR::from(pairing_aad(header, kem_ct)),
        CBOR::from(message_id),
        CBOR::from(valid_until),
        CBOR::from(signing_pub_key.clone()),
        CBOR::from(encapsulation_pub_key.clone()),
    ])
    .to_cbor_data()
}

fn decrypt_payload(
    key: &SymmetricKey,
    encrypted: &bc_components::EncryptedMessage,
) -> Result<PairingPayload, QlError> {
    let plaintext = key
        .decrypt(encrypted)
        .map_err(|_| QlError::InvalidPayload)?;
    let cbor = CBOR::try_from_data(plaintext).map_err(|_| QlError::InvalidPayload)?;
    PairingPayload::try_from(cbor).map_err(|_| QlError::InvalidPayload)
}

fn ensure_not_expired(_message_id: MessageId, valid_until: u64) -> Result<(), QlError> {
    if now_secs() > valid_until {
        Err(QlError::InvalidPayload)
    } else {
        Ok(())
    }
}

fn pairing_aad(header: &QlHeader, kem_ct: &bc_components::EncapsulationCiphertext) -> Vec<u8> {
    CBOR::from(vec![CBOR::from(header.clone()), CBOR::from(kem_ct.clone())]).to_cbor_data()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
