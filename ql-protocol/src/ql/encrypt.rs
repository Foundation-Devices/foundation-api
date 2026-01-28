use std::{
    cmp::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};

use bc_components::{
    EncapsulationCiphertext, EncryptedMessage, Signature, Signer, SymmetricKey, Verifier, ARID, XID,
};
use dcbor::CBOR;

use super::{HandshakeKind, PendingHandshake, QlError, QlPeer, QlPlatform, ResetOrigin};
use crate::{MessageKind, QlHeader};

pub(crate) fn encrypt_payload_for_recipient(
    platform: &dyn QlPlatform,
    recipient: XID,
    kind: MessageKind,
    message_id: ARID,
    payload: CBOR,
) -> Result<(QlHeader, EncryptedMessage), QlError> {
    let peer = platform.lookup_peer_or_fail(recipient)?;
    let (session_key, kem_ct, should_sign_header) = match peer.session() {
        Some(session_key) => (session_key, None, false),
        None => create_session(peer, message_id)?,
    };
    let valid_until = now_secs().saturating_add(platform.message_expiration().as_secs());
    Ok(encrypt_payload_with_header(
        kind,
        message_id,
        platform.xid(),
        recipient,
        valid_until,
        kem_ct,
        should_sign_header,
        platform.signer(),
        &session_key,
        payload,
    ))
}

pub(crate) fn encrypt_response(
    platform: &dyn QlPlatform,
    recipient: XID,
    message_id: ARID,
    payload: CBOR,
) -> Result<(QlHeader, EncryptedMessage), QlError> {
    let peer = platform.lookup_peer_or_fail(recipient)?;
    let session_key = peer.session().ok_or(QlError::MissingSession(recipient))?;
    let valid_until = now_secs().saturating_add(platform.message_expiration().as_secs());
    Ok(encrypt_payload_with_header(
        MessageKind::Response,
        message_id,
        platform.xid(),
        recipient,
        valid_until,
        None,
        false,
        platform.signer(),
        &session_key,
        payload,
    ))
}

pub(crate) fn verify_header(platform: &dyn QlPlatform, header: &QlHeader) -> Result<(), QlError> {
    ensure_not_expired(header)?;
    if header.kem_ct.is_none() {
        return Ok(());
    }
    let signature = header.signature.as_ref().ok_or(QlError::InvalidSignature)?;
    let peer = platform.lookup_peer_or_fail(header.sender)?;
    let signing_key = peer.signing_pub_key();
    let signing_data = header.aad_data();
    if signing_key.verify(signature, &signing_data) {
        Ok(())
    } else {
        Err(QlError::InvalidSignature)
    }
}

pub(crate) fn ensure_not_expired(header: &QlHeader) -> Result<(), QlError> {
    let now = now_secs();
    if now > header.valid_until {
        Err(QlError::Expired)
    } else {
        Ok(())
    }
}

pub(crate) fn session_key_for_header(
    platform: &dyn QlPlatform,
    peer: &dyn QlPeer,
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

pub(crate) fn sign_reset_header(
    signer: &dyn Signer,
    header_unsigned: &QlHeader,
) -> Option<Signature> {
    let signing_data = header_unsigned.aad_data();
    Some(signer.sign(&signing_data).expect("failed to sign header"))
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn sign_header(
    signer: &dyn Signer,
    signing_data: &[u8],
    should_sign_header: bool,
) -> Option<Signature> {
    if should_sign_header {
        Some(signer.sign(&signing_data).expect("failed to sign header"))
    } else {
        None
    }
}

fn encrypt_payload_with_header(
    kind: MessageKind,
    message_id: ARID,
    sender: XID,
    recipient: XID,
    valid_until: u64,
    kem_ct: Option<EncapsulationCiphertext>,
    should_sign_header: bool,
    signer: &dyn Signer,
    session_key: &SymmetricKey,
    payload: CBOR,
) -> (QlHeader, EncryptedMessage) {
    let header_unsigned = QlHeader {
        kind,
        id: message_id,
        sender,
        recipient,
        valid_until,
        kem_ct: kem_ct.clone(),
        signature: None,
    };
    let aad = header_unsigned.aad_data();
    let payload_bytes = payload.to_cbor_data();
    let encrypted = session_key.encrypt(
        payload_bytes,
        Some(aad.clone()),
        None::<bc_components::Nonce>,
    );
    let signature = sign_header(signer, &aad, should_sign_header);
    let header = QlHeader {
        signature,
        ..header_unsigned
    };
    (header, encrypted)
}

fn create_session(
    peer: &dyn QlPeer,
    message_id: ARID,
) -> Result<(SymmetricKey, Option<EncapsulationCiphertext>, bool), QlError> {
    let recipient_key = peer.encapsulation_pub_key();
    let (session_key, kem_ct) = recipient_key.encapsulate_new_shared_secret();
    peer.store_session(session_key.clone());
    peer.set_pending_handshake(Some(PendingHandshake {
        kind: HandshakeKind::SessionInit,
        origin: ResetOrigin::Local,
        id: message_id,
    }));
    Ok((session_key, Some(kem_ct), true))
}

pub(crate) fn handshake_cmp(local: (XID, ARID), peer: (XID, ARID)) -> Ordering {
    match peer.0.cmp(&local.0) {
        Ordering::Equal => peer.1.data().cmp(local.1.data()),
        order => order,
    }
}

#[cfg(test)]
pub(crate) fn encrypt_test_payload(data: &[u8]) -> EncryptedMessage {
    let key = SymmetricKey::new();
    key.encrypt(data, None::<Vec<u8>>, None::<bc_components::Nonce>)
}

#[cfg(test)]
mod tests {
    use bc_components::ARID;
    use dcbor::CBOR;

    use super::*;
    use crate::{encode_ql_message, test_identity::TestIdentity};

    #[test]
    fn message_size_without_session() {
        let sender = TestIdentity::generate();
        let recipient = TestIdentity::generate();
        let (session_key, kem_ct) = recipient
            .encapsulation_public_key
            .encapsulate_new_shared_secret();
        let (header, encrypted) = encrypt_payload_with_header(
            MessageKind::Request,
            ARID::new(),
            sender.xid,
            recipient.xid,
            123,
            Some(kem_ct),
            true,
            &sender.private_keys,
            &session_key,
            CBOR::from("size"),
        );

        let bytes = encode_ql_message(header.clone(), encrypted);
        println!("message size without session: {} bytes", bytes.len());
        assert!(header.kem_ct.is_some());
        assert!(header.signature.is_some());
        assert!(!bytes.is_empty());
    }

    #[test]
    fn message_size_with_session() {
        let sender = TestIdentity::generate();
        let recipient = TestIdentity::generate();
        let session_key = SymmetricKey::new();
        let (header, encrypted) = encrypt_payload_with_header(
            MessageKind::Request,
            ARID::new(),
            sender.xid,
            recipient.xid,
            123,
            None,
            false,
            &sender.private_keys,
            &session_key,
            CBOR::from("size"),
        );

        let bytes = encode_ql_message(header.clone(), encrypted);
        println!("message size with session: {} bytes", bytes.len());
        assert!(header.kem_ct.is_none());
        assert!(header.signature.is_none());
        assert!(!bytes.is_empty());
    }
}
