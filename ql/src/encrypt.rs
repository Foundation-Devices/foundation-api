use std::{cmp::Ordering, time::Duration};

use bc_components::{
    EncapsulationCiphertext, EncapsulationPublicKey, Nonce, Signature, Signer, SigningPublicKey,
    SymmetricKey, Verifier, XID,
};
use dcbor::CBOR;

use crate::{
    platform::{HandshakeKind, PendingHandshake, QlPeer, QlPlatform, QlPlatformExt, ResetOrigin},
    wire::{
        DecryptedMessage, EncryptedMessage, MessageKind, Nack, PairingPayload, QlDetails,
        QlEnvelope, QlHeader,
    },
    MessageId, QlError, RouteId,
};

pub(crate) fn encrypt_payload_for_recipient(
    platform: &impl QlPlatform,
    recipient: XID,
    kind: MessageKind,
    message_id: MessageId,
    route_id: RouteId,
    payload: CBOR,
    expiration: Duration,
) -> Result<EncryptedMessage, QlError> {
    let peer = platform.lookup_peer_or_fail(recipient)?;
    let (session_key, kem_ct, should_sign_header) = match peer.session() {
        Some(session_key) => (session_key, None, false),
        None => create_session(&peer, message_id),
    };
    let valid_until = now_secs().saturating_add(expiration.as_secs());
    let envelope = QlEnvelope {
        message_id,
        valid_until,
        route_id,
        payload,
    };
    let header_unsigned = QlHeader {
        kind,
        sender: platform.xid(),
        recipient,
        kem_ct: kem_ct.clone(),
        signature: None,
    };
    let aad = header_unsigned.aad_data();
    let payload_bytes = CBOR::from(envelope).to_cbor_data();
    let encrypted = session_key.encrypt(payload_bytes, Some(aad.clone()), None::<Nonce>);
    let signature = sign_header(platform.signer(), &aad, should_sign_header);
    let header = QlHeader {
        signature,
        ..header_unsigned
    };
    Ok(EncryptedMessage { header, encrypted })
}

pub(crate) fn encrypt_response(
    platform: &impl QlPlatform,
    recipient: XID,
    message_id: MessageId,
    payload: CBOR,
    kind: MessageKind,
    expiration: Duration,
) -> Result<EncryptedMessage, QlError> {
    let peer = platform.lookup_peer_or_fail(recipient)?;
    let session_key = peer.session().ok_or(QlError::MissingSession(recipient))?;
    let valid_until = now_secs().saturating_add(expiration.as_secs());
    let envelope = QlEnvelope {
        message_id,
        valid_until,
        route_id: RouteId::new(0),
        payload,
    };
    let header = QlHeader {
        kind,
        sender: platform.xid(),
        recipient,
        kem_ct: None,
        signature: None,
    };
    let aad = header.aad_data();
    let payload_bytes = CBOR::from(envelope).to_cbor_data();
    let encrypted = session_key.encrypt(payload_bytes, Some(aad), None::<Nonce>);
    Ok(EncryptedMessage { header, encrypted })
}

pub(crate) fn encrypt_pairing_request(
    platform: &impl QlPlatform,
    recipient_signing_key: &SigningPublicKey,
    recipient_encapsulation_key: &EncapsulationPublicKey,
    message_id: MessageId,
    expiration: Duration,
) -> EncryptedMessage {
    let (session_key, kem_ct) = recipient_encapsulation_key.encapsulate_new_shared_secret();
    let recipient = XID::new(recipient_signing_key);
    let valid_until = now_secs().saturating_add(expiration.as_secs());
    let header = QlHeader {
        kind: MessageKind::Pairing,
        sender: platform.xid(),
        recipient,
        kem_ct: Some(kem_ct),
        signature: None,
    };
    let signing_pub_key = platform.signing_key().clone();
    let encapsulation_pub_key = platform.encapsulation_public_key();
    let proof_data = pairing_proof_data(
        &header,
        message_id,
        valid_until,
        &signing_pub_key,
        &encapsulation_pub_key,
    );
    let proof = platform
        .signer()
        .sign(&proof_data)
        .expect("failed to sign pairing payload");
    let payload = PairingPayload {
        signing_pub_key,
        encapsulation_pub_key,
        proof,
    };
    let envelope = QlEnvelope {
        message_id,
        valid_until,
        route_id: RouteId::new(0),
        payload: CBOR::from(payload),
    };
    let payload_bytes = CBOR::from(envelope).to_cbor_data();
    let encrypted = session_key.encrypt(payload_bytes, Some(header.aad_data()), None::<Nonce>);
    EncryptedMessage { header, encrypted }
}

pub(crate) fn decrypt_pairing_payload(
    platform: &impl QlPlatform,
    EncryptedMessage { header, encrypted }: EncryptedMessage,
) -> Result<(PairingPayload, SymmetricKey), QlError> {
    let kem_ct = header.kem_ct.as_ref().ok_or(QlError::InvalidPayload)?;
    let session_key = platform.decapsulate_shared_secret(kem_ct)?;
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), &encrypted)?;
    let envelope = QlEnvelope::try_from(decrypted).map_err(QlError::Decode)?;
    ensure_not_expired(envelope.message_id, envelope.valid_until)?;
    let pairing = PairingPayload::try_from(envelope.payload).map_err(QlError::Decode)?;
    if XID::new(&pairing.signing_pub_key) != header.sender {
        return Err(QlError::InvalidPayload);
    }
    let proof_data = pairing_proof_data(
        &header,
        envelope.message_id,
        envelope.valid_until,
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
        platform.decapsulate_shared_secret(kem_ct)
    } else {
        peer.session().ok_or(QlError::MissingSession(header.sender))
    }
}

pub(crate) fn extract_reset_payload(
    platform: &impl QlPlatform,
    EncryptedMessage { header, encrypted }: EncryptedMessage,
) -> Result<(), QlError> {
    verify_header(platform, &header)?;
    let peer = platform.lookup_peer_or_fail(header.sender)?;
    let (envelope, session_key) = decrypt_envelope(platform, &peer, &header, &encrypted)?;
    ensure_not_expired(envelope.message_id, envelope.valid_until)?;
    if let Some(pending) = peer.pending_handshake() {
        if pending.kind == HandshakeKind::SessionReset && pending.origin == ResetOrigin::Local {
            let cmp = handshake_cmp(
                (platform.xid(), pending.id),
                (header.sender, envelope.message_id),
            );
            if cmp != Ordering::Less {
                return Ok(());
            }
        }
    }
    peer.store_session(session_key.clone());
    peer.set_pending_handshake(Some(PendingHandshake {
        kind: HandshakeKind::SessionReset,
        origin: ResetOrigin::Peer,
        id: envelope.message_id,
    }));
    if !envelope.payload.is_null() {
        return Err(QlError::InvalidPayload);
    }
    Ok(())
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
    message_id: MessageId,
    valid_until: u64,
    signing_pub_key: &SigningPublicKey,
    encapsulation_pub_key: &EncapsulationPublicKey,
) -> Vec<u8> {
    CBOR::from(vec![
        CBOR::from(header.aad_data()),
        CBOR::from(message_id),
        CBOR::from(valid_until),
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
    message_id: MessageId,
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

fn handshake_cmp(local: (XID, MessageId), peer: (XID, MessageId)) -> Ordering {
    match peer.0.cmp(&local.0) {
        Ordering::Equal => peer.1.cmp(&local.1),
        order => order,
    }
}

fn ensure_not_expired(id: MessageId, valid_until: u64) -> Result<(), QlError> {
    let now = now_secs();
    if now > valid_until {
        Err(QlError::Nack {
            id,
            nack: Nack::Expired,
        })
    } else {
        Ok(())
    }
}

pub(crate) fn extract_envelope(
    platform: &impl QlPlatform,
    EncryptedMessage { header, encrypted }: EncryptedMessage,
) -> Result<DecryptedMessage, QlError> {
    verify_header(platform, &header)?;
    let peer = platform.lookup_peer_or_fail(header.sender)?;
    let (envelope, session_key) = decrypt_envelope(platform, &peer, &header, &encrypted)?;
    ensure_not_expired(envelope.message_id, envelope.valid_until)?;
    if header.kem_ct.is_some() {
        ensure_session_init_order(platform, &peer, header.sender, envelope.message_id)?;
        peer.store_session(session_key.clone());
    }
    peer.set_pending_handshake(None);
    let details = QlDetails::from_parts(&header, &envelope);
    Ok(DecryptedMessage {
        header: details,
        payload: envelope.payload,
    })
}

pub(crate) fn decrypt_envelope(
    platform: &impl QlPlatform,
    peer: &impl QlPeer,
    header: &QlHeader,
    payload: &bc_components::EncryptedMessage,
) -> Result<(QlEnvelope, SymmetricKey), QlError> {
    let session_key = session_key_for_header(platform, peer, header)?;
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), payload)?;
    let envelope = QlEnvelope::try_from(decrypted)?;
    Ok((envelope, session_key))
}

fn ensure_session_init_order(
    platform: &impl QlPlatform,
    peer: &impl QlPeer,
    sender: XID,
    envelope_id: MessageId,
) -> Result<(), QlError> {
    if let Some(pending) = peer.pending_handshake() {
        if pending.kind == HandshakeKind::SessionInit && pending.origin == ResetOrigin::Local {
            let cmp = handshake_cmp((platform.xid(), pending.id), (sender, envelope_id));
            if cmp != Ordering::Less {
                return Err(QlError::SessionInitCollision);
            }
        }
    }
    Ok(())
}
