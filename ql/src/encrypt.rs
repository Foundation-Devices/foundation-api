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
    MessageId, QlError, RouteId, SessionEpoch,
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
        Some(session_key) => {
            let epoch = peer.session_epoch().ok_or(QlError::InvalidPayload)?;
            SessionSetup::Existing { session_key, epoch }
        }
        None => {
            let (session_key, kem_ct, epoch) = create_session(&peer, message_id);
            SessionSetup::Init {
                session_key,
                kem_ct,
                epoch,
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
        SessionSetup::Existing { session_key, epoch } => {
            let header = QlHeader::Message {
                sender: platform.xid(),
                recipient,
                epoch,
                session: SessionState::Established,
            };
            let aad = header.aad_data();
            (session_key, header, aad)
        }
        SessionSetup::Init {
            session_key,
            kem_ct,
            epoch,
        } => {
            let aad = QlHeader::message_init_aad(platform.xid(), recipient, epoch, &kem_ct);
            let signature = sign_header(platform.signer(), &aad);
            let header = QlHeader::Message {
                sender: platform.xid(),
                recipient,
                epoch,
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
    let epoch = peer.session_epoch().ok_or(QlError::InvalidPayload)?;
    let valid_until = now_secs().saturating_add(expiration.as_secs());
    let envelope = QlEnvelope {
        message_id,
        valid_until,
        kind,
        route_id: RouteId::new(0),
        payload,
    };
    let header = QlHeader::Message {
        sender: platform.xid(),
        recipient,
        epoch,
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
        QlHeader::Message {
            sender,
            session: SessionState::Init { signature, .. },
            ..
        } => (*sender, signature),
        QlHeader::SessionReset {
            sender, signature, ..
        } => (*sender, signature),
        QlHeader::Pairing { .. }
        | QlHeader::Message {
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
        | QlHeader::Message {
            session: SessionState::Init { kem_ct, .. },
            ..
        } => platform.decapsulate_shared_secret(kem_ct),
        QlHeader::Message {
            sender,
            epoch,
            session: SessionState::Established,
            ..
        } => {
            let Some(current_epoch) = peer.session_epoch() else {
                return Err(QlError::MissingSession(*sender));
            };
            if *epoch != current_epoch {
                return Err(QlError::StaleSession);
            }
            peer.session().ok_or(QlError::MissingSession(*sender))
        }
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
    let mut has_local_pending = false;
    if let Some(pending) = peer.pending_session() {
        if pending.kind == SessionKind::SessionReset && pending.origin == ResetOrigin::Local {
            has_local_pending = true;
            match payload.session_epoch.cmp(&pending.epoch) {
                Ordering::Less => return Ok(()),
                Ordering::Equal => {
                    if !peer_session_wins(
                        (platform.xid(), pending.epoch),
                        (sender, payload.session_epoch),
                    ) {
                        return Ok(());
                    }
                }
                Ordering::Greater => {}
            }
        }
    }
    if !has_local_pending {
        if let Some(current_epoch) = peer.session_epoch() {
            if payload.session_epoch <= current_epoch {
                return Ok(());
            }
        }
    }
    peer.store_session_key(session_key.clone());
    peer.set_session_epoch(Some(payload.session_epoch));
    peer.set_pending_session(Some(PendingSession {
        kind: SessionKind::SessionReset,
        origin: ResetOrigin::Peer,
        id: payload.message_id,
        epoch: payload.session_epoch,
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
        epoch: SessionEpoch,
    },
    Init {
        session_key: SymmetricKey,
        kem_ct: EncapsulationCiphertext,
        epoch: SessionEpoch,
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
) -> (SymmetricKey, EncapsulationCiphertext, SessionEpoch) {
    let recipient_key = peer.encapsulation_pub_key();
    let (session_key, kem_ct) = recipient_key.encapsulate_new_shared_secret();
    let epoch = next_session_epoch(peer);
    peer.store_session_key(session_key.clone());
    peer.set_session_epoch(Some(epoch));
    peer.set_pending_session(Some(PendingSession {
        kind: SessionKind::SessionInit,
        origin: ResetOrigin::Local,
        id: message_id,
        epoch,
    }));
    (session_key, kem_ct, epoch)
}

fn next_session_epoch(peer: &impl QlPeer) -> SessionEpoch {
    peer.session_epoch()
        .map(SessionEpoch::next)
        .unwrap_or_else(|| SessionEpoch::new(1))
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
    if !matches!(header, QlHeader::Message { .. }) {
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
        QlHeader::Message {
            session: SessionState::Init { .. },
            ..
        }
    ) {
        let epoch = match header {
            QlHeader::Message { epoch, .. } => epoch,
            _ => return Err(EnvelopeError::Error(QlError::InvalidPayload)),
        };
        ensure_session_init_order(platform, &peer, sender, epoch).map_err(EnvelopeError::Error)?;
        peer.store_session_key(session_key.clone());
        peer.set_session_epoch(Some(epoch));
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
    epoch: SessionEpoch,
) -> Result<(), QlError> {
    if let Some(pending) = peer.pending_session() {
        if pending.kind == SessionKind::SessionInit && pending.origin == ResetOrigin::Local {
            match epoch.cmp(&pending.epoch) {
                Ordering::Less => return Err(QlError::StaleSession),
                Ordering::Equal => {
                    if !peer_session_wins((platform.xid(), pending.epoch), (sender, epoch)) {
                        return Err(QlError::SessionInitCollision);
                    }
                }
                Ordering::Greater => {}
            }
            return Ok(());
        }
    }
    if let Some(current_epoch) = peer.session_epoch() {
        if epoch <= current_epoch {
            return Err(QlError::StaleSession);
        }
    }
    Ok(())
}

fn peer_session_wins(local: (XID, SessionEpoch), peer: (XID, SessionEpoch)) -> bool {
    match peer.1.cmp(&local.1) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => peer.0 < local.0,
    }
}
