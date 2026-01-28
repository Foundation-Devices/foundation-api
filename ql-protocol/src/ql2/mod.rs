use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, HashMap, VecDeque},
    time::{Duration, Instant},
};

use bc_components::{
    EncapsulationCiphertext, EncapsulationPrivateKey, EncapsulationPublicKey, EncryptedMessage,
    Signer, SigningPublicKey, SymmetricKey, ARID, XID,
};
use dcbor::CBOR;

use crate::{
    executor::ExecutorError,
    ql::{HandshakeKind, Nack, PendingHandshake, QlError, QlPayload, ResetOrigin},
    wire::{decode_ql_message, encode_ql_message, DecodeError, MessageKind, QlHeader, QlMessage},
    RequestConfig,
};

pub mod encrypt;

#[derive(Debug)]
pub enum Output<T> {
    None,
    One(T),
    Many(Vec<T>),
}

impl<T> Default for Output<T> {
    fn default() -> Self {
        Self::None
    }
}

impl<T> Output<T> {
    pub fn push(&mut self, value: T) {
        match std::mem::replace(self, Output::None) {
            Output::None => {
                *self = Output::One(value);
            }
            Output::One(existing) => {
                *self = Output::Many(vec![existing, value]);
            }
            Output::Many(mut values) => {
                values.push(value);
                *self = Output::Many(values);
            }
        }
    }

    pub fn extend(&mut self, other: Output<T>) {
        match other {
            Output::None => {}
            Output::One(value) => self.push(value),
            Output::Many(values) => {
                for value in values {
                    self.push(value);
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum CoreOutput {
    RequestCompleted {
        id: ARID,
        payload: CBOR,
    },
    RequestFailed {
        id: ARID,
        error: QlError,
    },
    IncomingRequest {
        token: ReplyToken,
        header: QlHeader,
        payload: QlPayload,
    },
    IncomingEvent {
        header: QlHeader,
        payload: QlPayload,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct ReplyToken {
    pub id: ARID,
    pub recipient: XID,
}

#[derive(Debug)]
pub struct OutboundItem {
    pub id: ARID,
    pub bytes: Vec<u8>,
}

pub trait QlPeer {
    fn encapsulation_pub_key(&self) -> &EncapsulationPublicKey;
    fn signing_pub_key(&self) -> &SigningPublicKey;
    fn session(&self) -> Option<SymmetricKey>;
    fn store_session(&mut self, key: SymmetricKey);
    fn pending_handshake(&self) -> Option<PendingHandshake>;
    fn set_pending_handshake(&mut self, handshake: Option<PendingHandshake>);
}

pub trait QlPlatform {
    type Peer: QlPeer;

    fn lookup_peer(&mut self, peer: XID) -> Option<&mut Self::Peer>;
    fn lookup_peer_or_fail(&mut self, peer: XID) -> Result<&mut Self::Peer, QlError> {
        self.lookup_peer(peer)
            .ok_or_else(|| QlError::UnknownPeer(peer))
    }

    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey;
    fn encapsulation_public_key(&self) -> EncapsulationPublicKey;
    fn signing_key(&self) -> &SigningPublicKey;
    fn message_expiration(&self) -> Duration;
    fn signer(&self) -> &dyn Signer;
    fn store_peer(
        &mut self,
        signing_pub_key: SigningPublicKey,
        encapsulation_pub_key: EncapsulationPublicKey,
        session: SymmetricKey,
    ) -> Result<(), QlError>;

    fn xid(&self) -> XID {
        XID::new(self.signing_key())
    }

    fn decapsulate_shared_secret(
        &self,
        ciphertext: &EncapsulationCiphertext,
    ) -> Result<SymmetricKey, QlError> {
        self.encapsulation_private_key()
            .decapsulate_shared_secret(ciphertext)
            .map_err(|_| QlError::InvalidPayload)
    }

    fn decrypt_message(
        &self,
        key: &SymmetricKey,
        header_aad: &[u8],
        payload: &EncryptedMessage,
    ) -> Result<CBOR, QlError> {
        if payload.aad() != header_aad {
            return Err(QlError::InvalidPayload);
        }
        let plaintext = key.decrypt(payload).map_err(|_| QlError::InvalidPayload)?;
        Ok(CBOR::try_from_data(plaintext)?)
    }
}

pub struct QlCoreConfig {
    pub default_timeout: Duration,
}

pub struct QlCore<P>
where
    P: QlPlatform,
{
    platform: P,
    timeouts: BinaryHeap<Reverse<TimeoutEntry>>,
    outbound: VecDeque<OutboundItem>,
    config: QlCoreConfig,
}

#[derive(Debug, Clone)]
struct TimeoutEntry {
    deadline: Instant,
    id: ARID,
}

impl PartialEq for TimeoutEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline
    }
}

impl Eq for TimeoutEntry {}

impl PartialOrd for TimeoutEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimeoutEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.deadline.cmp(&other.deadline)
    }
}

impl<P> QlCore<P>
where
    P: QlPlatform,
{
    pub fn new(platform: P, config: QlCoreConfig) -> Self {
        Self {
            platform,
            timeouts: BinaryHeap::new(),
            outbound: VecDeque::new(),
            config,
        }
    }

    pub fn send_request<M>(
        &mut self,
        message: M,
        recipient: XID,
        request_config: RequestConfig,
    ) -> Result<ARID, QlError>
    where
        M: crate::ql::RequestResponse,
    {
        let payload = QlPayload {
            message_id: M::ID,
            payload: message.into(),
        };
        let message_id = ARID::new();
        let (header, encrypted) = encrypt::encrypt_payload_for_recipient(
            &mut self.platform,
            recipient,
            MessageKind::Request,
            message_id,
            payload.into(),
        )?;
        let bytes = encode_ql_message(header, encrypted);
        self.outbound.push_back(OutboundItem {
            id: message_id,
            bytes,
        });

        let effective_timeout = request_config
            .timeout
            .unwrap_or(self.config.default_timeout);
        if effective_timeout.is_zero() {
            return Err(QlError::Send(ExecutorError::Timeout));
        }
        let deadline = Instant::now() + effective_timeout;
        self.timeouts.push(Reverse(TimeoutEntry {
            deadline,
            id: message_id,
        }));
        Ok(message_id)
    }

    pub fn send_event<M>(&mut self, message: M, recipient: XID) -> Result<(), QlError>
    where
        M: crate::ql::Event,
    {
        let payload = QlPayload {
            message_id: M::ID,
            payload: message.into(),
        };
        let message_id = ARID::new();
        let (header, encrypted) = encrypt::encrypt_payload_for_recipient(
            &mut self.platform,
            recipient,
            MessageKind::Event,
            message_id,
            payload.into(),
        )?;
        let bytes = encode_ql_message(header, encrypted);
        self.outbound.push_back(OutboundItem {
            id: message_id,
            bytes,
        });
        Ok(())
    }

    pub fn send_pairing_request(
        &mut self,
        recipient_signing_key: &SigningPublicKey,
        recipient_encapsulation_key: &EncapsulationPublicKey,
    ) -> Result<(), QlError> {
        let (header, encrypted) = encrypt::encrypt_pairing_request(
            &mut self.platform,
            recipient_signing_key,
            recipient_encapsulation_key,
        )?;
        let message_id = header.id;
        let bytes = encode_ql_message(header, encrypted);
        self.outbound.push_back(OutboundItem {
            id: message_id,
            bytes,
        });
        Ok(())
    }

    pub fn next_outbound(&mut self) -> Option<OutboundItem> {
        self.outbound.pop_front()
    }

    pub fn respond(&mut self, token: ReplyToken, payload: CBOR) -> Result<(), QlError> {
        let (header, encrypted) = encrypt::encrypt_response_with_kind(
            &mut self.platform,
            token.recipient,
            token.id,
            payload,
            MessageKind::Response,
        )?;
        let bytes = encode_ql_message(header, encrypted);
        self.outbound.push_back(OutboundItem {
            id: token.id,
            bytes,
        });
        Ok(())
    }

    pub fn respond_nack(&mut self, token: ReplyToken, reason: Nack) -> Result<(), QlError> {
        let (header, encrypted) = match encrypt::encrypt_response_with_kind(
            &mut self.platform,
            token.recipient,
            token.id,
            CBOR::from(reason),
            MessageKind::Nack,
        ) {
            Ok(result) => result,
            Err(QlError::MissingSession(_)) => return Ok(()),
            Err(error) => return Err(error),
        };
        let bytes = encode_ql_message(header, encrypted);
        self.outbound.push_back(OutboundItem {
            id: token.id,
            bytes,
        });
        Ok(())
    }

    pub fn handle_incoming(&mut self, bytes: Vec<u8>) -> Option<CoreOutput> {
        let message = match decode_ql_message(&bytes) {
            Ok(message) => message,
            Err(context) => {
                if let Some(header) = context.header {
                    if header.kind == MessageKind::Response || header.kind == MessageKind::Nack {
                        let error = match context.error {
                            DecodeError::Cbor(error) => QlError::Decode(error),
                        };
                        return Some(CoreOutput::RequestFailed {
                            id: header.id,
                            error,
                        });
                    }
                }
                return None;
            }
        };

        if message.header.kind == MessageKind::Pairing {
            if let Ok((payload, session_key)) = encrypt::decrypt_pairing_payload(
                &mut self.platform,
                &message.header,
                &message.payload,
            ) {
                let _ = self.platform.store_peer(
                    payload.signing_pub_key,
                    payload.encapsulation_pub_key,
                    session_key,
                );
            }
            return None;
        }

        if message.header.kind == MessageKind::Response || message.header.kind == MessageKind::Nack
        {
            return self.handle_response(message);
        }

        if encrypt::verify_header(&mut self.platform, &message.header).is_err() {
            return None;
        }

        let sender = message.header.sender;
        let request_id = message.header.id;
        match message.header.kind {
            MessageKind::Request => {
                let payload = match extract_typed_payload(
                    &mut self.platform,
                    &message.header,
                    message.payload,
                ) {
                    Ok(payload) => payload,
                    Err(QlError::Decode(_)) => {
                        let _ = self.respond_nack(
                            ReplyToken {
                                id: request_id,
                                recipient: sender,
                            },
                            Nack::InvalidPayload,
                        );
                        return None;
                    }
                    Err(error) => {
                        if matches!(error, QlError::MissingSession(_) | QlError::InvalidPayload) {
                            let _ = self.send_session_reset(sender);
                        }
                        return None;
                    }
                };
                Some(CoreOutput::IncomingRequest {
                    token: ReplyToken {
                        id: request_id,
                        recipient: sender,
                    },
                    header: message.header,
                    payload,
                })
            }
            MessageKind::Event => {
                let payload = match extract_typed_payload(
                    &mut self.platform,
                    &message.header,
                    message.payload,
                ) {
                    Ok(payload) => payload,
                    Err(error) => {
                        if matches!(error, QlError::MissingSession(_) | QlError::InvalidPayload) {
                            let _ = self.send_session_reset(sender);
                        }
                        return None;
                    }
                };
                Some(CoreOutput::IncomingEvent {
                    header: message.header,
                    payload,
                })
            }
            MessageKind::SessionReset => {
                let _ = extract_reset_payload(&mut self.platform, &message.header, message.payload);
                None
            }
            MessageKind::Pairing | MessageKind::Response | MessageKind::Nack => None,
        }
    }

    pub fn tick(&mut self, now: Instant) -> Output<CoreOutput> {
        let mut output = Output::default();
        while let Some(Reverse(entry)) = self.timeouts.peek().cloned() {
            if entry.deadline > now {
                break;
            }
            self.timeouts.pop();
            output.push(CoreOutput::RequestFailed {
                id: entry.id,
                error: QlError::Send(ExecutorError::Timeout),
            });
        }
        output
    }

    fn send_session_reset(&mut self, recipient: XID) -> Result<(), QlError> {
        let sender = self.platform.xid();
        let valid_until =
            encrypt::now_secs().saturating_add(self.platform.message_expiration().as_secs());
        let peer = match self.platform.lookup_peer_or_fail(recipient) {
            Ok(peer) => peer,
            Err(error) => return Err(error),
        };
        let recipient_key = peer.encapsulation_pub_key();
        let (session_key, kem_ct) = recipient_key.encapsulate_new_shared_secret();
        peer.store_session(session_key.clone());
        let id = bc_components::ARID::new();
        peer.set_pending_handshake(Some(PendingHandshake {
            kind: HandshakeKind::SessionReset,
            origin: ResetOrigin::Local,
            id,
        }));
        let header_unsigned = QlHeader {
            kind: MessageKind::SessionReset,
            id,
            sender,
            recipient,
            valid_until,
            kem_ct: Some(kem_ct.clone()),
            signature: None,
        };
        let aad = header_unsigned.aad_data();
        let payload_bytes = CBOR::null().to_cbor_data();
        let encrypted = session_key.encrypt(payload_bytes, Some(aad), None::<bc_components::Nonce>);
        let signature = encrypt::sign_reset_header(self.platform.signer(), &header_unsigned);
        let header = QlHeader {
            signature,
            ..header_unsigned
        };
        let bytes = encode_ql_message(header, encrypted);
        self.outbound.push_back(OutboundItem { id, bytes });
        Ok(())
    }

    fn handle_response(&mut self, message: QlMessage) -> Option<CoreOutput> {
        let header = message.header.clone();
        if let Err(error) = encrypt::verify_header(&mut self.platform, &header) {
            return Some(CoreOutput::RequestFailed {
                id: header.id,
                error,
            });
        }
        let session_key = match self.resolve_session_key(&header) {
            Ok(key) => key,
            Err(error) => {
                return Some(CoreOutput::RequestFailed {
                    id: header.id,
                    error,
                });
            }
        };
        let decrypted =
            match self
                .platform
                .decrypt_message(&session_key, &header.aad_data(), &message.payload)
            {
                Ok(payload) => payload,
                Err(error) => {
                    return Some(CoreOutput::RequestFailed {
                        id: header.id,
                        error,
                    });
                }
            };
        self.timeouts.retain(|e| e.0.id != header.id);
        if let Ok(peer) = self.platform.lookup_peer_or_fail(header.sender) {
            peer.set_pending_handshake(None);
        }
        if header.kind == MessageKind::Nack {
            let nack = Nack::try_from(decrypted).unwrap_or(Nack::Unknown);
            return Some(CoreOutput::RequestFailed {
                id: header.id,
                error: QlError::Nack(nack),
            });
        }
        Some(CoreOutput::RequestCompleted {
            id: header.id,
            payload: decrypted,
        })
    }

    fn resolve_session_key(&mut self, header: &QlHeader) -> Result<SymmetricKey, QlError> {
        if let Some(kem_ct) = &header.kem_ct {
            let local_xid = self.platform.xid();
            let pending = match self.platform.lookup_peer_or_fail(header.sender) {
                Ok(peer) => peer.pending_handshake(),
                Err(_) => None,
            };
            if let Some(pending) = pending {
                if pending.kind == HandshakeKind::SessionInit
                    && pending.origin == ResetOrigin::Local
                {
                    let cmp =
                        encrypt::handshake_cmp((local_xid, pending.id), (header.sender, header.id));
                    if cmp != Ordering::Less {
                        return Err(QlError::SessionInitCollision);
                    }
                }
            }
            let key = self.platform.decapsulate_shared_secret(kem_ct)?;
            if let Ok(peer) = self.platform.lookup_peer_or_fail(header.sender) {
                peer.store_session(key.clone());
            }
            Ok(key)
        } else {
            let peer = self.platform.lookup_peer_or_fail(header.sender)?;
            peer.session().ok_or(QlError::MissingSession(header.sender))
        }
    }
}

fn extract_typed_payload<P>(
    platform: &mut P,
    header: &QlHeader,
    payload: EncryptedMessage,
) -> Result<QlPayload, QlError>
where
    P: QlPlatform,
{
    let session_key = if let Some(kem_ct) = &header.kem_ct {
        let local_xid = platform.xid();
        if let Ok(peer) = platform.lookup_peer_or_fail(header.sender) {
            if let Some(pending) = peer.pending_handshake() {
                if pending.kind == HandshakeKind::SessionInit
                    && pending.origin == ResetOrigin::Local
                {
                    let cmp =
                        encrypt::handshake_cmp((local_xid, pending.id), (header.sender, header.id));
                    if cmp != Ordering::Less {
                        return Err(QlError::SessionInitCollision);
                    }
                }
            }
        }
        let key = platform.decapsulate_shared_secret(kem_ct)?;
        if let Ok(peer) = platform.lookup_peer_or_fail(header.sender) {
            peer.store_session(key.clone());
        }
        key
    } else {
        let peer = platform.lookup_peer_or_fail(header.sender)?;
        peer.session()
            .ok_or(QlError::MissingSession(header.sender))?
    };
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), &payload)?;
    if let Ok(peer) = platform.lookup_peer_or_fail(header.sender) {
        peer.set_pending_handshake(None);
    }
    QlPayload::try_from(decrypted).map_err(QlError::Decode)
}

fn extract_reset_payload<P>(
    platform: &mut P,
    header: &QlHeader,
    payload: EncryptedMessage,
) -> Result<(), QlError>
where
    P: QlPlatform,
{
    let local_xid = platform.xid();
    if let Ok(peer) = platform.lookup_peer_or_fail(header.sender) {
        if let Some(pending) = peer.pending_handshake() {
            if pending.kind == HandshakeKind::SessionReset && pending.origin == ResetOrigin::Local {
                let cmp =
                    encrypt::handshake_cmp((local_xid, pending.id), (header.sender, header.id));
                if cmp != Ordering::Less {
                    return Ok(());
                }
            }
        }
    }
    let kem_ct = header.kem_ct.as_ref().ok_or(QlError::InvalidPayload)?;
    let session_key = platform.decapsulate_shared_secret(kem_ct)?;
    if let Ok(peer) = platform.lookup_peer_or_fail(header.sender) {
        peer.store_session(session_key.clone());
        peer.set_pending_handshake(Some(PendingHandshake {
            kind: HandshakeKind::SessionReset,
            origin: ResetOrigin::Peer,
            id: header.id,
        }));
    }
    let decrypted = platform.decrypt_message(&session_key, &header.aad_data(), &payload)?;
    if !decrypted.is_null() {
        return Err(QlError::InvalidPayload);
    }
    Ok(())
}
