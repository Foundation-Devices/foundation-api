use std::{
    cmp::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};

use bc_components::{
    EncapsulationCiphertext, EncapsulationPublicKey, EncryptedMessage, Nonce, Signature, Signer,
    SigningPublicKey, SymmetricKey, Verifier, ARID, XID,
};
use dcbor::CBOR;
use thiserror::Error;

use crate::runtime::{
    HandshakeKind, PendingHandshake, QlPeer, QlPlatform, ResetOrigin, RuntimeError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Response,
    Event,
    SessionReset,
    Pairing,
    Nack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nack {
    Unknown,
    UnknownMessage,
    InvalidPayload,
}

#[derive(Debug, Clone)]
pub struct QlHeader {
    pub kind: MessageKind,
    pub id: ARID,
    pub sender: XID,
    pub recipient: XID,
    pub valid_until: u64,
    pub kem_ct: Option<EncapsulationCiphertext>,
    pub signature: Option<Signature>,
}

#[derive(Debug, Clone)]
pub struct QlPayload {
    pub message_id: u64,
    pub payload: CBOR,
}

#[derive(Debug, Clone)]
pub struct QlMessage {
    pub header: QlHeader,
    pub payload: EncryptedMessage,
}

impl QlHeader {
    pub fn aad_data(&self) -> Vec<u8> {
        header_cbor_unsigned(
            self.kind,
            self.id,
            self.sender,
            self.recipient,
            self.valid_until,
            self.kem_ct.clone(),
        )
        .to_cbor_data()
    }
}

impl From<QlHeader> for CBOR {
    fn from(value: QlHeader) -> Self {
        header_cbor(
            value.kind,
            value.id,
            value.sender,
            value.recipient,
            value.valid_until,
            value.kem_ct,
            value.signature,
        )
    }
}

impl TryFrom<CBOR> for QlHeader {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        let [kind_cbor, id_cbor, sender_cbor, recipient_cbor, valid_until_cbor, kem_ct_cbor, signature_cbor] =
            cbor_array::<7>(array)?;
        let kind = kind_cbor.try_into()?;
        let id = id_cbor.try_into()?;
        let sender = sender_cbor.try_into()?;
        let recipient = recipient_cbor.try_into()?;
        let valid_until = valid_until_cbor.try_into()?;
        let kem_ct = option_from_cbor(kem_ct_cbor)?;
        let signature = option_from_cbor(signature_cbor)?;
        Ok(Self {
            kind,
            id,
            sender,
            recipient,
            valid_until,
            kem_ct,
            signature,
        })
    }
}

impl From<QlPayload> for CBOR {
    fn from(value: QlPayload) -> Self {
        CBOR::from(vec![CBOR::from(value.message_id), value.payload])
    }
}

impl TryFrom<CBOR> for QlPayload {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        let [message_id, payload] = cbor_array::<2>(array)?;
        let message_id = message_id.try_into()?;
        Ok(Self {
            message_id,
            payload,
        })
    }
}

impl From<MessageKind> for CBOR {
    fn from(value: MessageKind) -> Self {
        let kind = match value {
            MessageKind::Request => 1,
            MessageKind::Response => 2,
            MessageKind::Event => 3,
            MessageKind::SessionReset => 4,
            MessageKind::Pairing => 5,
            MessageKind::Nack => 6,
        };
        CBOR::from(kind)
    }
}

impl TryFrom<CBOR> for MessageKind {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let kind: u64 = value.try_into()?;
        match kind {
            1 => Ok(MessageKind::Request),
            2 => Ok(MessageKind::Response),
            3 => Ok(MessageKind::Event),
            4 => Ok(MessageKind::SessionReset),
            5 => Ok(MessageKind::Pairing),
            6 => Ok(MessageKind::Nack),
            _ => Err(dcbor::Error::msg("unknown message kind")),
        }
    }
}

impl From<Nack> for CBOR {
    fn from(value: Nack) -> Self {
        let value = match value {
            Nack::Unknown => 0,
            Nack::UnknownMessage => 1,
            Nack::InvalidPayload => 2,
        };
        CBOR::from(value)
    }
}

impl TryFrom<CBOR> for Nack {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let value: u64 = value.try_into()?;
        Ok(match value {
            1 => Nack::UnknownMessage,
            2 => Nack::InvalidPayload,
            _ => Nack::Unknown,
        })
    }
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error(transparent)]
    Cbor(#[from] dcbor::Error),
}

#[derive(Debug)]
pub struct DecodeErrContext {
    pub error: DecodeError,
    pub header: Option<QlHeader>,
}

pub fn encode_ql_message(header: QlHeader, payload: EncryptedMessage) -> Vec<u8> {
    let cbor = CBOR::from(vec![CBOR::from(header), CBOR::from(payload)]);
    cbor.to_cbor_data()
}

pub fn decode_ql_message(bytes: &[u8]) -> Result<QlMessage, DecodeErrContext> {
    let cbor = dcbor::CBOR::try_from_data(bytes).map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: None,
    })?;
    let array = cbor.try_into_array().map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: None,
    })?;
    let [header_cbor, payload_cbor] = cbor_array::<2>(array).map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: None,
    })?;
    let header = QlHeader::try_from(header_cbor).map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: None,
    })?;
    let payload: EncryptedMessage = payload_cbor.try_into().map_err(|error| DecodeErrContext {
        error: DecodeError::Cbor(error),
        header: Some(header.clone()),
    })?;
    Ok(QlMessage { header, payload })
}

pub(crate) fn encrypt_payload_for_recipient(
    platform: &dyn QlPlatform,
    recipient: XID,
    kind: MessageKind,
    message_id: ARID,
    payload: CBOR,
) -> Result<(QlHeader, EncryptedMessage), RuntimeError> {
    let peer = platform.lookup_peer_or_fail(recipient)?;
    let (session_key, kem_ct, should_sign_header) = match peer.session() {
        Some(session_key) => (session_key, None, false),
        None => create_session(peer, message_id)?,
    };
    let valid_until = now_secs().saturating_add(platform.message_expiration().as_secs());
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
    platform: &dyn QlPlatform,
    recipient: XID,
    message_id: ARID,
    payload: CBOR,
    kind: MessageKind,
) -> Result<(QlHeader, EncryptedMessage), RuntimeError> {
    let peer = platform.lookup_peer_or_fail(recipient)?;
    let session_key = peer
        .session()
        .ok_or(RuntimeError::MissingSession(recipient))?;
    let valid_until = now_secs().saturating_add(platform.message_expiration().as_secs());
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
    platform: &dyn QlPlatform,
    recipient_signing_key: &SigningPublicKey,
    recipient_encapsulation_key: &EncapsulationPublicKey,
) -> Result<(QlHeader, EncryptedMessage), RuntimeError> {
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
    let encrypted = session_key.encrypt(payload_bytes, Some(header.aad_data()), None::<Nonce>);
    Ok((header, encrypted))
}

pub(crate) fn decrypt_pairing_payload(
    platform: &dyn QlPlatform,
    header: &QlHeader,
    payload: &EncryptedMessage,
) -> Result<(PairingPayload, SymmetricKey), RuntimeError> {
    ensure_not_expired(header)?;
    let kem_ct = header.kem_ct.as_ref().ok_or(RuntimeError::InvalidPayload)?;
    let session_key = platform.decapsulate_shared_secret(kem_ct)?;
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), payload)?;
    let pairing = PairingPayload::try_from(decrypted).map_err(RuntimeError::Decode)?;
    if XID::new(&pairing.signing_pub_key) != header.sender {
        return Err(RuntimeError::InvalidPayload);
    }
    let proof_data = pairing_proof_data(
        header,
        &pairing.signing_pub_key,
        &pairing.encapsulation_pub_key,
    );
    if pairing.signing_pub_key.verify(&pairing.proof, &proof_data) {
        Ok((pairing, session_key))
    } else {
        Err(RuntimeError::InvalidSignature)
    }
}

pub(crate) fn verify_header(
    platform: &dyn QlPlatform,
    header: &QlHeader,
) -> Result<(), RuntimeError> {
    ensure_not_expired(header)?;
    if header.kem_ct.is_none() {
        return Ok(());
    }
    let signature = header
        .signature
        .as_ref()
        .ok_or(RuntimeError::InvalidSignature)?;
    let peer = platform.lookup_peer_or_fail(header.sender)?;
    let signing_key = peer.signing_pub_key();
    if signing_key.verify(signature, &header.aad_data()) {
        Ok(())
    } else {
        Err(RuntimeError::InvalidSignature)
    }
}

pub(crate) fn session_key_for_header(
    platform: &dyn QlPlatform,
    peer: &dyn QlPeer,
    header: &QlHeader,
) -> Result<SymmetricKey, RuntimeError> {
    if let Some(kem_ct) = &header.kem_ct {
        if let Some(pending) = peer.pending_handshake() {
            if pending.kind == HandshakeKind::SessionInit && pending.origin == ResetOrigin::Local {
                let cmp = handshake_cmp((platform.xid(), pending.id), (header.sender, header.id));
                if cmp != Ordering::Less {
                    return Err(RuntimeError::SessionInitCollision);
                }
            }
        }
        let key = platform.decapsulate_shared_secret(kem_ct)?;
        peer.store_session(key.clone());
        Ok(key)
    } else {
        peer.session()
            .ok_or(RuntimeError::MissingSession(header.sender))
    }
}

pub(crate) fn extract_payload(
    platform: &dyn QlPlatform,
    header: &QlHeader,
    payload: EncryptedMessage,
) -> Result<QlPayload, RuntimeError> {
    let peer = platform.lookup_peer_or_fail(header.sender)?;
    let session_key = session_key_for_header(platform, peer, header)?;
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), &payload)?;
    peer.set_pending_handshake(None);
    QlPayload::try_from(decrypted).map_err(RuntimeError::Decode)
}

pub(crate) fn extract_reset_payload(
    platform: &dyn QlPlatform,
    header: &QlHeader,
    payload: EncryptedMessage,
) -> Result<(), RuntimeError> {
    let peer = platform.lookup_peer_or_fail(header.sender)?;
    if let Some(pending) = peer.pending_handshake() {
        if pending.kind == HandshakeKind::SessionReset && pending.origin == ResetOrigin::Local {
            let cmp = handshake_cmp((platform.xid(), pending.id), (header.sender, header.id));
            if cmp != Ordering::Less {
                return Ok(());
            }
        }
    }
    let kem_ct = header.kem_ct.as_ref().ok_or(RuntimeError::InvalidPayload)?;
    let session_key = platform.decapsulate_shared_secret(kem_ct)?;
    peer.store_session(session_key.clone());
    peer.set_pending_handshake(Some(PendingHandshake {
        kind: HandshakeKind::SessionReset,
        origin: ResetOrigin::Peer,
        id: header.id,
    }));
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), &payload)?;
    if !decrypted.is_null() {
        return Err(RuntimeError::InvalidPayload);
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn sign_header(signer: &dyn Signer, signing_data: &[u8], sign_header: bool) -> Option<Signature> {
    if sign_header {
        Some(signer.sign(&signing_data).expect("failed to sign header"))
    } else {
        None
    }
}

fn create_session(
    peer: &dyn QlPeer,
    message_id: ARID,
) -> Result<(SymmetricKey, Option<EncapsulationCiphertext>, bool), RuntimeError> {
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

fn handshake_cmp(local: (XID, ARID), peer: (XID, ARID)) -> Ordering {
    match peer.0.cmp(&local.0) {
        Ordering::Equal => peer.1.data().cmp(local.1.data()),
        order => order,
    }
}

fn ensure_not_expired(header: &QlHeader) -> Result<(), RuntimeError> {
    let now = now_secs();
    if now > header.valid_until {
        Err(RuntimeError::Expired)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PairingPayload {
    pub(crate) signing_pub_key: SigningPublicKey,
    pub(crate) encapsulation_pub_key: EncapsulationPublicKey,
    proof: Signature,
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

fn option_to_cbor<T>(value: Option<T>) -> CBOR
where
    T: Into<CBOR>,
{
    value.map_or_else(CBOR::null, Into::into)
}

fn option_from_cbor<T>(value: CBOR) -> Result<Option<T>, dcbor::Error>
where
    T: TryFrom<CBOR, Error = dcbor::Error>,
{
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(T::try_from(value)?))
    }
}

fn cbor_array<const N: usize>(array: Vec<CBOR>) -> Result<[CBOR; N], dcbor::Error> {
    if array.len() != N {
        return Err(dcbor::Error::msg("invalid array length"));
    }
    array
        .try_into()
        .map_err(|_| dcbor::Error::msg("invalid array length"))
}

fn header_cbor(
    kind: MessageKind,
    id: ARID,
    sender: XID,
    recipient: XID,
    valid_until: u64,
    kem_ct: Option<EncapsulationCiphertext>,
    signature: Option<Signature>,
) -> CBOR {
    CBOR::from(vec![
        CBOR::from(kind),
        CBOR::from(id),
        CBOR::from(sender),
        CBOR::from(recipient),
        CBOR::from(valid_until),
        option_to_cbor(kem_ct),
        option_to_cbor(signature),
    ])
}

fn header_cbor_unsigned(
    kind: MessageKind,
    id: ARID,
    sender: XID,
    recipient: XID,
    valid_until: u64,
    kem_ct: Option<EncapsulationCiphertext>,
) -> CBOR {
    CBOR::from(vec![
        CBOR::from(kind),
        CBOR::from(id),
        CBOR::from(sender),
        CBOR::from(recipient),
        CBOR::from(valid_until),
        option_to_cbor(kem_ct),
    ])
}
