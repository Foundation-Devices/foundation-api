use std::{cmp::Ordering, time::Duration};

use bc_components::{
    EncapsulationCiphertext, EncapsulationPublicKey, EncryptedMessage, Nonce, Signature, Signer,
    SigningPublicKey, SymmetricKey, Verifier, ARID, XID,
};
use dcbor::CBOR;

use crate::{
    platform::{HandshakeKind, PendingHandshake, QlPeer, QlPlatform, QlPlatformExt, ResetOrigin},
    wire::{MessageKind, PairingPayload, QlHeader, QlPayload},
    QlError,
};

pub(crate) fn encrypt_payload_for_recipient(
    platform: &impl QlPlatform,
    recipient: XID,
    kind: MessageKind,
    message_id: ARID,
    payload: CBOR,
    expiration: Duration,
) -> Result<(QlHeader, EncryptedMessage), QlError> {
    let peer = platform.lookup_peer_or_fail(recipient)?;
    let (session_key, kem_ct, should_sign_header) = match peer.session() {
        Some(session_key) => (session_key, None, false),
        None => create_session(&peer, message_id),
    };
    let valid_until = now_secs().saturating_add(expiration.as_secs());
    let header_unsigned = QlHeader {
        kind,
        id: message_id,
        sender: platform.xid(),
        recipient,
        valid_until,
        kem_ct: kem_ct.clone(),
        signature: None,
    };
    let aad = header_unsigned.aad_data();
    let payload_bytes = payload.to_cbor_data();
    let encrypted = session_key.encrypt(payload_bytes, Some(aad.clone()), None::<Nonce>);
    let signature = sign_header(platform.signer(), &aad, should_sign_header);
    let header = QlHeader {
        signature,
        ..header_unsigned
    };
    Ok((header, encrypted))
}

pub(crate) fn encrypt_response(
    platform: &impl QlPlatform,
    recipient: XID,
    message_id: ARID,
    payload: CBOR,
    kind: MessageKind,
    expiration: Duration,
) -> Result<(QlHeader, EncryptedMessage), QlError> {
    let peer = platform.lookup_peer_or_fail(recipient)?;
    let session_key = peer.session().ok_or(QlError::MissingSession(recipient))?;
    let valid_until = now_secs().saturating_add(expiration.as_secs());
    let header_unsigned = QlHeader {
        kind,
        id: message_id,
        sender: platform.xid(),
        recipient,
        valid_until,
        kem_ct: None,
        signature: None,
    };
    let aad = header_unsigned.aad_data();
    let payload_bytes = payload.to_cbor_data();
    let encrypted = session_key.encrypt(payload_bytes, Some(aad), None::<Nonce>);
    Ok((header_unsigned, encrypted))
}

pub(crate) fn encrypt_pairing_request(
    platform: &impl QlPlatform,
    recipient_signing_key: &SigningPublicKey,
    recipient_encapsulation_key: &EncapsulationPublicKey,
    expiration: Duration,
) -> (QlHeader, EncryptedMessage) {
    let (session_key, kem_ct) = recipient_encapsulation_key.encapsulate_new_shared_secret();
    let recipient = XID::new(recipient_signing_key);
    let message_id = ARID::new();
    let valid_until = now_secs().saturating_add(expiration.as_secs());
    let header = QlHeader {
        kind: MessageKind::Pairing,
        id: message_id,
        sender: platform.xid(),
        recipient,
        valid_until,
        kem_ct: Some(kem_ct),
        signature: None,
    };
    let signing_pub_key = platform.signing_key().clone();
    let encapsulation_pub_key = platform.encapsulation_public_key();
    let proof_data = pairing_proof_data(&header, &signing_pub_key, &encapsulation_pub_key);
    let proof = platform
        .signer()
        .sign(&proof_data)
        .expect("failed to sign pairing payload");
    let payload = PairingPayload {
        signing_pub_key,
        encapsulation_pub_key,
        proof,
    };
    let payload_bytes = CBOR::from(payload).to_cbor_data();
    let encrypted = session_key.encrypt(payload_bytes, Some(header.aad_data()), None::<Nonce>);
    (header, encrypted)
}

pub(crate) fn decrypt_pairing_payload(
    platform: &impl QlPlatform,
    header: &QlHeader,
    payload: &EncryptedMessage,
) -> Result<(PairingPayload, SymmetricKey), QlError> {
    ensure_not_expired(header)?;
    let kem_ct = header.kem_ct.as_ref().ok_or(QlError::InvalidPayload)?;
    let session_key = platform.decapsulate_shared_secret(kem_ct)?;
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), payload)?;
    let pairing = PairingPayload::try_from(decrypted).map_err(QlError::Decode)?;
    if XID::new(&pairing.signing_pub_key) != header.sender {
        return Err(QlError::InvalidPayload);
    }
    let proof_data = pairing_proof_data(
        header,
        &pairing.signing_pub_key,
        &pairing.encapsulation_pub_key,
    );
    if pairing.signing_pub_key.verify(&pairing.proof, &proof_data) {
        Ok((pairing, session_key))
    } else {
        Err(QlError::InvalidSignature)
    }
}

pub(crate) fn verify_header(platform: &impl QlPlatform, header: &QlHeader) -> Result<(), QlError> {
    ensure_not_expired(header)?;
    if header.kem_ct.is_none() {
        return Ok(());
    }
    let signature = header.signature.as_ref().ok_or(QlError::InvalidSignature)?;
    let peer = platform.lookup_peer_or_fail(header.sender)?;
    let signing_key = peer.signing_pub_key();
    if signing_key.verify(signature, &header.aad_data()) {
        Ok(())
    } else {
        Err(QlError::InvalidSignature)
    }
}

pub(crate) fn session_key_for_header(
    platform: &impl QlPlatform,
    peer: &impl QlPeer,
    header: &QlHeader,
) -> Result<SymmetricKey, QlError> {
    if let Some(kem_ct) = &header.kem_ct {
        if let Some(pending) = peer.pending_handshake() {
            if pending.kind == HandshakeKind::SessionInit && pending.origin == ResetOrigin::Local {
                let cmp = handshake_cmp((platform.xid(), pending.id), (header.sender, header.id));
                if cmp != Ordering::Less {
                    return Err(QlError::SessionInitCollision);
                }
            }
        }
        let key = platform.decapsulate_shared_secret(kem_ct)?;
        peer.store_session(key.clone());
        Ok(key)
    } else {
        peer.session().ok_or(QlError::MissingSession(header.sender))
    }
}

pub(crate) fn extract_payload(
    platform: &impl QlPlatform,
    header: &QlHeader,
    payload: EncryptedMessage,
) -> Result<QlPayload, QlError> {
    let peer = platform.lookup_peer_or_fail(header.sender)?;
    let session_key = session_key_for_header(platform, &peer, header)?;
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), &payload)?;
    peer.set_pending_handshake(None);
    QlPayload::try_from(decrypted).map_err(QlError::Decode)
}

pub(crate) fn extract_reset_payload(
    platform: &impl QlPlatform,
    header: &QlHeader,
    payload: EncryptedMessage,
) -> Result<(), QlError> {
    let peer = platform.lookup_peer_or_fail(header.sender)?;
    if let Some(pending) = peer.pending_handshake() {
        if pending.kind == HandshakeKind::SessionReset && pending.origin == ResetOrigin::Local {
            let cmp = handshake_cmp((platform.xid(), pending.id), (header.sender, header.id));
            if cmp != Ordering::Less {
                return Ok(());
            }
        }
    }
    let kem_ct = header.kem_ct.as_ref().ok_or(QlError::InvalidPayload)?;
    let session_key = platform.decapsulate_shared_secret(kem_ct)?;
    peer.store_session(session_key.clone());
    peer.set_pending_handshake(Some(PendingHandshake {
        kind: HandshakeKind::SessionReset,
        origin: ResetOrigin::Peer,
        id: header.id,
    }));
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), &payload)?;
    if !decrypted.is_null() {
        return Err(QlError::InvalidPayload);
    }
    Ok(())
}

pub(crate) fn extract_heartbeat_payload(
    platform: &impl QlPlatform,
    header: &QlHeader,
    payload: EncryptedMessage,
) -> Result<(), QlError> {
    let peer = platform.lookup_peer_or_fail(header.sender)?;
    let session_key = session_key_for_header(platform, &peer, header)?;
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), &payload)?;
    peer.set_pending_handshake(None);
    if decrypted.is_null() {
        Ok(())
    } else {
        Err(QlError::InvalidPayload)
    }
}

pub(crate) fn sign_reset_header(
    signer: &dyn Signer,
    header_unsigned: &QlHeader,
) -> Option<Signature> {
    let signing_data = header_unsigned.aad_data();
    Some(signer.sign(&signing_data).expect("failed to sign header"))
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn pairing_proof_data(
    header: &QlHeader,
    signing_pub_key: &SigningPublicKey,
    encapsulation_pub_key: &EncapsulationPublicKey,
) -> Vec<u8> {
    CBOR::from(vec![
        CBOR::from(header.aad_data()),
        CBOR::from(signing_pub_key.clone()),
        CBOR::from(encapsulation_pub_key.clone()),
    ])
    .to_cbor_data()
}

fn sign_header(signer: &dyn Signer, signing_data: &[u8], sign_header: bool) -> Option<Signature> {
    if sign_header {
        Some(signer.sign(&signing_data).expect("failed to sign header"))
    } else {
        None
    }
}

fn create_session(
    peer: &impl QlPeer,
    message_id: ARID,
) -> (SymmetricKey, Option<EncapsulationCiphertext>, bool) {
    let recipient_key = peer.encapsulation_pub_key();
    let (session_key, kem_ct) = recipient_key.encapsulate_new_shared_secret();
    peer.store_session(session_key.clone());
    peer.set_pending_handshake(Some(PendingHandshake {
        kind: HandshakeKind::SessionInit,
        origin: ResetOrigin::Local,
        id: message_id,
    }));
    (session_key, Some(kem_ct), true)
}

fn handshake_cmp(local: (XID, ARID), peer: (XID, ARID)) -> Ordering {
    match peer.0.cmp(&local.0) {
        Ordering::Equal => peer.1.data().cmp(local.1.data()),
        order => order,
    }
}

fn ensure_not_expired(header: &QlHeader) -> Result<(), QlError> {
    let now = now_secs();
    if now > header.valid_until {
        Err(QlError::Expired)
    } else {
        Ok(())
    }
}
