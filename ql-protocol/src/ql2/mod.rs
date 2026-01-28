use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, HashMap, VecDeque},
    marker::PhantomData,
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
    RequestCompleted { id: ARID, payload: CBOR },
    RequestFailed { id: ARID, error: QlError },
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

pub trait RequestHandler<M, P>
where
    M: crate::ql::RequestResponse,
    P: QlPlatform,
{
    fn handle<'a>(&mut self, request: QlRequest<'a, M, P>);
    fn default_response() -> M::Response;
}

pub trait EventHandler<M>
where
    M: crate::ql::Event,
{
    fn handle(&mut self, event: M);
}

pub struct QlRequest<'a, M, P>
where
    M: crate::ql::RequestResponse,
    P: QlPlatform,
{
    pub message: M,
    pub responder: QlResponder<'a, M::Response, P>,
}

struct ResponderState<R> {
    response: Option<R>,
}

pub struct QlResponder<'a, R, P>
where
    P: QlPlatform,
{
    state: &'a mut ResponderState<R>,
    _marker: PhantomData<P>,
}

impl<'a, R, P> QlResponder<'a, R, P>
where
    P: QlPlatform,
{
    pub fn respond(self, response: R) -> Result<(), QlError> {
        self.state.response = Some(response);
        Ok(())
    }
}

pub struct QlCoreConfig {
    pub default_timeout: Duration,
}

pub struct QlCore<S, P>
where
    P: QlPlatform,
{
    platform: P,
    handlers: HashMap<u64, RouterHandler<S, P>>,
    pending: HashMap<ARID, PendingEntry>,
    timeouts: BinaryHeap<Reverse<TimeoutEntry>>,
    outbound: VecDeque<Vec<u8>>,
    config: QlCoreConfig,
}

type RouterHandler<S, P> = fn(&mut S, RouterEvent, &mut QlCore<S, P>) -> Result<(), QlError>;

enum RouterEvent {
    Event {
        #[allow(unused)]
        header: QlHeader,
        payload: QlPayload,
    },
    Request {
        header: QlHeader,
        payload: QlPayload,
        responder: ResponderContext,
    },
    SessionReset {
        #[allow(dead_code)]
        header: QlHeader,
    },
}

struct ResponderContext {
    request_id: ARID,
    recipient: XID,
}

impl RouterEvent {
    fn message_id(&self) -> u64 {
        match self {
            RouterEvent::Event { payload, .. } => payload.message_id,
            RouterEvent::Request { payload, .. } => payload.message_id,
            RouterEvent::SessionReset { .. } => 0,
        }
    }
}

struct PendingEntry;

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

impl<S, P> QlCore<S, P>
where
    P: QlPlatform,
{
    pub fn new(platform: P, config: QlCoreConfig) -> Self {
        Self {
            platform,
            handlers: HashMap::new(),
            pending: HashMap::new(),
            timeouts: BinaryHeap::new(),
            outbound: VecDeque::new(),
            config,
        }
    }

    pub fn add_request_handler<M>(self) -> Self
    where
        M: crate::ql::RequestResponse,
        S: RequestHandler<M, P>,
    {
        self.add_handler(M::ID, handle_request::<M, S, P>)
    }

    pub fn add_event_handler<M>(self) -> Self
    where
        M: crate::ql::Event,
        S: EventHandler<M>,
    {
        self.add_handler(M::ID, handle_event::<M, S, P>)
    }

    fn add_handler(mut self, id: u64, handler: RouterHandler<S, P>) -> Self {
        if self.handlers.insert(id, handler).is_some() {
            panic!("duplicate message_id {id}")
        }
        self
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
        self.outbound.push_back(bytes);

        let effective_timeout = request_config
            .timeout
            .unwrap_or(self.config.default_timeout);
        if effective_timeout.is_zero() {
            return Err(QlError::Send(ExecutorError::Timeout));
        }
        let deadline = Instant::now() + effective_timeout;
        self.pending.insert(message_id, PendingEntry);
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
        self.outbound.push_back(bytes);
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
        let bytes = encode_ql_message(header, encrypted);
        self.outbound.push_back(bytes);
        Ok(())
    }

    pub fn handle_incoming(&mut self, state: &mut S, bytes: Vec<u8>) -> Option<CoreOutput> {
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

        if let Err(error) = encrypt::verify_header(&mut self.platform, &message.header) {
            return Some(CoreOutput::RequestFailed {
                id: message.header.id,
                error,
            });
        }

        let sender = message.header.sender;
        let message_id = message.header.id;
        let kind = message.header.kind;
        let event = match decrypt_event(&mut self.platform, message) {
            Ok(event) => event,
            Err(error) => {
                if kind == MessageKind::Request && matches!(error, QlError::Decode(_)) {
                    let _ = self.send_nack(
                        ResponderContext {
                            request_id: message_id,
                            recipient: sender,
                        },
                        Nack::InvalidPayload,
                    );
                }
                if matches!(error, QlError::MissingSession(_) | QlError::InvalidPayload) {
                    let _ = self.send_session_reset(sender);
                }
                return Some(CoreOutput::RequestFailed {
                    id: message_id,
                    error,
                });
            }
        };

        match event {
            RouterEvent::SessionReset { .. } => return None,
            RouterEvent::Event { .. } => {
                let payload_id = event.message_id();
                let handler = match self.handlers.get(&payload_id) {
                    Some(handler) => handler,
                    None => {
                        return None;
                    }
                };
                if let Err(error) = handler(state, event, self) {
                    return Some(CoreOutput::RequestFailed {
                        id: message_id,
                        error,
                    });
                }
            }
            RouterEvent::Request { .. } => {
                let payload_id = event.message_id();
                let handler = match self.handlers.get(&payload_id) {
                    Some(handler) => handler,
                    None => {
                        let _ = self.send_nack(
                            ResponderContext {
                                request_id: message_id,
                                recipient: sender,
                            },
                            Nack::UnknownMessage,
                        );
                        return None;
                    }
                };
                if let Err(error) = handler(state, event, self) {
                    return Some(CoreOutput::RequestFailed {
                        id: message_id,
                        error,
                    });
                }
            }
        }

        None
    }

    pub fn tick(&mut self, now: Instant) -> Output<CoreOutput> {
        let mut output = Output::default();
        while let Some(Reverse(entry)) = self.timeouts.peek().cloned() {
            if entry.deadline > now {
                break;
            }
            self.timeouts.pop();
            if self.pending.remove(&entry.id).is_some() {
                output.push(CoreOutput::RequestFailed {
                    id: entry.id,
                    error: QlError::Send(ExecutorError::Timeout),
                });
            }
        }
        output
    }

    fn send_session_reset(&mut self, recipient: XID) -> Option<CoreOutput> {
        let sender = self.platform.xid();
        let valid_until =
            encrypt::now_secs().saturating_add(self.platform.message_expiration().as_secs());
        let peer = match self.platform.lookup_peer_or_fail(recipient) {
            Ok(peer) => peer,
            Err(error) => {
                return Some(CoreOutput::RequestFailed {
                    id: ARID::new(),
                    error,
                });
            }
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
        self.outbound.push_back(bytes);
        None
    }

    fn send_nack(&mut self, responder: ResponderContext, reason: Nack) -> Option<CoreOutput> {
        let (header, encrypted) = match encrypt::encrypt_response_with_kind(
            &mut self.platform,
            responder.recipient,
            responder.request_id,
            CBOR::from(reason),
            MessageKind::Nack,
        ) {
            Ok(result) => result,
            Err(QlError::MissingSession(_)) => return None,
            Err(error) => {
                return Some(CoreOutput::RequestFailed {
                    id: responder.request_id,
                    error,
                });
            }
        };
        let bytes = encode_ql_message(header, encrypted);
        self.outbound.push_back(bytes);
        None
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
        if let Ok(peer) = self.platform.lookup_peer_or_fail(header.sender) {
            peer.set_pending_handshake(None);
        }
        if self.pending.remove(&header.id).is_none() {
            return None;
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

fn handle_request<M, S, P>(
    state: &mut S,
    event: RouterEvent,
    core: &mut QlCore<S, P>,
) -> Result<(), QlError>
where
    M: crate::ql::RequestResponse,
    S: RequestHandler<M, P>,
    P: QlPlatform,
{
    let (_header, payload, responder_context) = match event {
        RouterEvent::Request {
            header,
            payload,
            responder,
        } => (header, payload, responder),
        RouterEvent::Event { .. } => unreachable!("expected request"),
        RouterEvent::SessionReset { .. } => unreachable!("expected request"),
    };

    let message = match M::try_from(payload.payload) {
        Ok(message) => message,
        Err(_error) => {
            let _ = core.send_nack(responder_context, Nack::InvalidPayload);
            return Ok(());
        }
    };

    let mut responder_state = ResponderState { response: None };
    let responder_handle = QlResponder {
        state: &mut responder_state,
        _marker: PhantomData,
    };
    state.handle(QlRequest {
        message,
        responder: responder_handle,
    });
    let response = responder_state.response.unwrap_or_else(S::default_response);
    let (header, encrypted) = encrypt::encrypt_response_with_kind(
        &mut core.platform,
        responder_context.recipient,
        responder_context.request_id,
        response.into(),
        MessageKind::Response,
    )?;
    let bytes = encode_ql_message(header, encrypted);
    core.outbound.push_back(bytes);
    Ok(())
}

fn handle_event<M, S, P>(
    state: &mut S,
    event: RouterEvent,
    _core: &mut QlCore<S, P>,
) -> Result<(), QlError>
where
    M: crate::ql::Event,
    S: EventHandler<M>,
    P: QlPlatform,
{
    let payload = match event {
        RouterEvent::Event { payload, .. } => payload,
        RouterEvent::Request { .. } => unreachable!("expected event"),
        RouterEvent::SessionReset { .. } => unreachable!("expected event"),
    };
    let message = M::try_from(payload.payload)?;
    state.handle(message);
    Ok(())
}

fn decrypt_event<P>(platform: &mut P, message: QlMessage) -> Result<RouterEvent, QlError>
where
    P: QlPlatform,
{
    let header = message.header;
    let sender = header.sender;
    let id = header.id;
    match header.kind {
        MessageKind::Request => {
            let payload = extract_typed_payload(platform, &header, message.payload)?;
            Ok(RouterEvent::Request {
                header,
                payload,
                responder: ResponderContext {
                    request_id: id,
                    recipient: sender,
                },
            })
        }
        MessageKind::Event => {
            let payload = extract_typed_payload(platform, &header, message.payload)?;
            Ok(RouterEvent::Event { header, payload })
        }
        MessageKind::SessionReset => {
            extract_reset_payload(platform, &header, message.payload)?;
            Ok(RouterEvent::SessionReset { header })
        }
        MessageKind::Pairing | MessageKind::Response | MessageKind::Nack => {
            unreachable!("handled earlier")
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
