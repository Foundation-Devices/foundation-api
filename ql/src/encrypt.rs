use std::{cmp::Ordering, time::Duration};

use bc_components::{
    EncapsulationCiphertext, EncapsulationPublicKey, Nonce, Signature, Signer, SigningPublicKey,
    SymmetricKey, Verifier, XID,
};
use dcbor::CBOR;

use crate::{
    platform::{PendingSession, QlPeer, QlPlatform, QlPlatformExt, ResetOrigin, SessionKind},
    wire::{
        DecryptedMessage, EncryptedMessage, MessageKind, Nack, PairingPayload, QlDetails,
        QlEnvelope, QlHeader, SessionPayload, SessionState,
    },
    MessageId, QlError, RouteId,
};

#[derive(Debug)]
pub(crate) enum EnvelopeError {
    Nack {
        id: MessageId,
        nack: Nack,
        kind: MessageKind,
    },
    Error(QlError),
}

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
    let session_setup = match peer.session() {
        Some(session_key) => SessionSetup::Existing { session_key },
        None => {
            let (session_key, kem_ct) = create_session(&peer, message_id);
            SessionSetup::Init {
                session_key,
                kem_ct,
            }
        }
    };
    let valid_until = now_secs().saturating_add(expiration.as_secs());
    let envelope = QlEnvelope {
        message_id,
        valid_until,
        kind,
        route_id,
        payload,
    };
    let payload_bytes = CBOR::from(envelope).to_cbor_data();
    let (session_key, header, aad) = match session_setup {
        SessionSetup::Existing { session_key } => {
            let header = QlHeader::Normal {
                sender: platform.xid(),
                recipient,
                session: SessionState::Established,
            };
            let aad = header.aad_data();
            (session_key, header, aad)
        }
        SessionSetup::Init {
            session_key,
            kem_ct,
        } => {
            let aad = QlHeader::normal_init_aad(platform.xid(), recipient, &kem_ct);
            let signature = sign_header(platform.signer(), &aad);
            let header = QlHeader::Normal {
                sender: platform.xid(),
                recipient,
                session: SessionState::Init { kem_ct, signature },
            };
            (session_key, header, aad)
        }
    };
    let encrypted = session_key.encrypt(payload_bytes, Some(aad), None::<Nonce>);
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
        kind,
        route_id: RouteId::new(0),
        payload,
    };
    let header = QlHeader::Normal {
        sender: platform.xid(),
        recipient,
        session: SessionState::Established,
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
    let header = QlHeader::Pairing {
        sender: platform.xid(),
        recipient,
        kem_ct: kem_ct.clone(),
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
        message_id,
        valid_until,
        signing_pub_key,
        encapsulation_pub_key,
        proof,
    };
    let payload_bytes = CBOR::from(payload).to_cbor_data();
    let encrypted = session_key.encrypt(payload_bytes, Some(header.aad_data()), None::<Nonce>);
    EncryptedMessage { header, encrypted }
}

pub(crate) fn decrypt_pairing_payload(
    platform: &impl QlPlatform,
    EncryptedMessage { header, encrypted }: EncryptedMessage,
) -> Result<(PairingPayload, SymmetricKey), QlError> {
    let (sender, kem_ct) = match &header {
        QlHeader::Pairing { sender, kem_ct, .. } => (*sender, kem_ct),
        _ => return Err(QlError::InvalidPayload),
    };
    let session_key = platform.decapsulate_shared_secret(kem_ct)?;
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), &encrypted)?;
    let pairing = PairingPayload::try_from(decrypted).map_err(QlError::Decode)?;
    ensure_not_expired(pairing.message_id, pairing.valid_until)?;
    if XID::new(&pairing.signing_pub_key) != sender {
        return Err(QlError::InvalidPayload);
    }
    let proof_data = pairing_proof_data(
        &header,
        pairing.message_id,
        pairing.valid_until,
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
    let (sender, signature) = match header {
        QlHeader::Normal {
            sender,
            session: SessionState::Init { signature, .. },
            ..
        } => (*sender, signature),
        QlHeader::SessionReset {
            sender, signature, ..
        } => (*sender, signature),
        QlHeader::Pairing { .. }
        | QlHeader::Normal {
            session: SessionState::Established,
            ..
        } => return Ok(()),
    };
    let peer = platform.lookup_peer_or_fail(sender)?;
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
    match header {
        QlHeader::Pairing { kem_ct, .. }
        | QlHeader::SessionReset { kem_ct, .. }
        | QlHeader::Normal {
            session: SessionState::Init { kem_ct, .. },
            ..
        } => platform.decapsulate_shared_secret(kem_ct),
        QlHeader::Normal {
            sender,
            session: SessionState::Established,
            ..
        } => peer.session().ok_or(QlError::MissingSession(*sender)),
    }
}

pub(crate) fn extract_reset_payload(
    platform: &impl QlPlatform,
    EncryptedMessage { header, encrypted }: EncryptedMessage,
) -> Result<(), QlError> {
    let sender = header.sender();
    if !matches!(header, QlHeader::SessionReset { .. }) {
        return Err(QlError::InvalidPayload);
    }
    verify_header(platform, &header)?;
    let peer = platform.lookup_peer_or_fail(sender)?;
    let (payload, session_key) = decrypt_session_payload(platform, &peer, &header, &encrypted)?;
    ensure_not_expired(payload.message_id, payload.valid_until)?;
    if let Some(pending) = peer.pending_session() {
        if pending.kind == SessionKind::SessionReset && pending.origin == ResetOrigin::Local {
            let cmp = handshake_cmp((platform.xid(), pending.id), (sender, payload.message_id));
            if cmp != Ordering::Less {
                return Ok(());
            }
        }
    }
    peer.store_session_key(session_key.clone());
    peer.set_pending_session(Some(PendingSession {
        kind: SessionKind::SessionReset,
        origin: ResetOrigin::Peer,
        id: payload.message_id,
    }));
    Ok(())
}

pub(crate) fn sign_header(signer: &dyn Signer, aad: &[u8]) -> Signature {
    signer.sign(&aad).expect("failed to sign header")
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

enum SessionSetup {
    Existing {
        session_key: SymmetricKey,
    },
    Init {
        session_key: SymmetricKey,
        kem_ct: EncapsulationCiphertext,
    },
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

// sign_header handles session init/reset signing

fn create_session(
    peer: &impl QlPeer,
    message_id: MessageId,
) -> (SymmetricKey, EncapsulationCiphertext) {
    let recipient_key = peer.encapsulation_pub_key();
    let (session_key, kem_ct) = recipient_key.encapsulate_new_shared_secret();
    peer.store_session_key(session_key.clone());
    peer.set_pending_session(Some(PendingSession {
        kind: SessionKind::SessionInit,
        origin: ResetOrigin::Local,
        id: message_id,
    }));
    (session_key, kem_ct)
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
) -> Result<DecryptedMessage, EnvelopeError> {
    if !matches!(header, QlHeader::Normal { .. }) {
        return Err(EnvelopeError::Error(QlError::InvalidPayload));
    }
    verify_header(platform, &header).map_err(EnvelopeError::Error)?;
    let sender = header.sender();
    let peer = platform
        .lookup_peer_or_fail(sender)
        .map_err(EnvelopeError::Error)?;
    let (envelope, session_key) =
        decrypt_envelope(platform, &peer, &header, &encrypted).map_err(EnvelopeError::Error)?;
    match ensure_not_expired(envelope.message_id, envelope.valid_until) {
        Ok(()) => {}
        Err(QlError::Nack { nack, .. }) => {
            return Err(EnvelopeError::Nack {
                id: envelope.message_id,
                nack,
                kind: envelope.kind,
            });
        }
        Err(error) => return Err(EnvelopeError::Error(error)),
    }
    if matches!(
        header,
        QlHeader::Normal {
            session: SessionState::Init { .. },
            ..
        }
    ) {
        ensure_session_init_order(platform, &peer, sender, envelope.message_id)
            .map_err(EnvelopeError::Error)?;
        peer.store_session_key(session_key.clone());
    }
    peer.set_pending_session(None);
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

fn decrypt_session_payload(
    platform: &impl QlPlatform,
    peer: &impl QlPeer,
    header: &QlHeader,
    payload: &bc_components::EncryptedMessage,
) -> Result<(SessionPayload, SymmetricKey), QlError> {
    let session_key = session_key_for_header(platform, peer, header)?;
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), payload)?;
    let session_payload = SessionPayload::try_from(decrypted)?;
    Ok((session_payload, session_key))
}

fn ensure_session_init_order(
    platform: &impl QlPlatform,
    peer: &impl QlPeer,
    sender: XID,
    envelope_id: MessageId,
) -> Result<(), QlError> {
    if let Some(pending) = peer.pending_session() {
        if pending.kind == SessionKind::SessionInit && pending.origin == ResetOrigin::Local {
            let cmp = handshake_cmp((platform.xid(), pending.id), (sender, envelope_id));
            if cmp != Ordering::Less {
                return Err(QlError::SessionInitCollision);
            }
        }
    }
    Ok(())
}
