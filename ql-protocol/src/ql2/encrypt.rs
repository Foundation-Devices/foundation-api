use std::{
    cmp::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};

use bc_components::{
    EncapsulationCiphertext, EncapsulationPublicKey, EncryptedMessage, Signature, Signer,
    SigningPublicKey, SymmetricKey, Verifier, ARID, XID,
};
use dcbor::CBOR;

use super::{QlPeer, QlPlatform};
use crate::{
    cbor::cbor_array,
    ql::{HandshakeKind, PendingHandshake, QlError, ResetOrigin},
    wire::{MessageKind, QlHeader},
};

pub(crate) fn encrypt_payload_for_recipient<P>(
    platform: &mut P,
    recipient: XID,
    kind: MessageKind,
    message_id: ARID,
    payload: CBOR,
) -> Result<(QlHeader, EncryptedMessage), QlError>
where
    P: QlPlatform,
{
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

pub(crate) fn encrypt_response_with_kind<P>(
    platform: &mut P,
    recipient: XID,
    message_id: ARID,
    payload: CBOR,
    kind: MessageKind,
) -> Result<(QlHeader, EncryptedMessage), QlError>
where
    P: QlPlatform,
{
    let peer = platform.lookup_peer_or_fail(recipient)?;
    let session_key = peer.session().ok_or(QlError::MissingSession(recipient))?;
    let valid_until = now_secs().saturating_add(platform.message_expiration().as_secs());
    Ok(encrypt_payload_with_header(
        kind,
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

pub(crate) fn encrypt_pairing_request<P>(
    platform: &mut P,
    recipient_signing_key: &SigningPublicKey,
    recipient_encapsulation_key: &EncapsulationPublicKey,
) -> Result<(QlHeader, EncryptedMessage), QlError>
where
    P: QlPlatform,
{
    let (session_key, kem_ct) = recipient_encapsulation_key.encapsulate_new_shared_secret();
    let recipient = XID::new(recipient_signing_key);
    let message_id = ARID::new();
    let valid_until = now_secs().saturating_add(platform.message_expiration().as_secs());
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
    let encrypted = session_key.encrypt(
        payload_bytes,
        Some(header.aad_data()),
        None::<bc_components::Nonce>,
    );
    Ok((header, encrypted))
}

pub(crate) fn decrypt_pairing_payload<P>(
    platform: &mut P,
    header: &QlHeader,
    payload: &EncryptedMessage,
) -> Result<(PairingPayload, SymmetricKey), QlError>
where
    P: QlPlatform,
{
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

pub(crate) fn verify_header<P>(platform: &mut P, header: &QlHeader) -> Result<(), QlError>
where
    P: QlPlatform,
{
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
    peer: &mut impl QlPeer,
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

#[derive(Debug, Clone)]
pub(crate) struct PairingPayload {
    pub signing_pub_key: SigningPublicKey,
    pub encapsulation_pub_key: EncapsulationPublicKey,
    pub proof: Signature,
}

impl From<PairingPayload> for CBOR {
    fn from(value: PairingPayload) -> Self {
        CBOR::from(vec![
            CBOR::from(value.signing_pub_key),
            CBOR::from(value.encapsulation_pub_key),
            CBOR::from(value.proof),
        ])
    }
}

impl TryFrom<CBOR> for PairingPayload {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        let [signing_pub_key, encapsulation_pub_key, proof] = cbor_array::<3>(array)?;
        Ok(Self {
            signing_pub_key: signing_pub_key.try_into()?,
            encapsulation_pub_key: encapsulation_pub_key.try_into()?,
            proof: proof.try_into()?,
        })
    }
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
