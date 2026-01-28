use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, HashMap, VecDeque},
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_channel::{Receiver, Sender, WeakSender};
use bc_components::{
    EncapsulationCiphertext, EncapsulationPrivateKey, EncapsulationPublicKey, EncryptedMessage,
    Nonce, Signer, SigningPublicKey, SymmetricKey, ARID, XID,
};
use dcbor::CBOR;
use thiserror::Error;

use crate::{
    wire::{
        decode_ql_message, decrypt_pairing_payload, encode_ql_message, encrypt_pairing_request,
        encrypt_payload_for_recipient, encrypt_response, extract_payload, extract_reset_payload,
        now_secs, session_key_for_header, sign_reset_header, verify_header, DecodeError,
        MessageKind, Nack, QlHeader, QlMessage, QlPayload,
    },
    Event, QlCodec, RequestResponse,
};

pub type PlatformFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetOrigin {
    Local,
    Peer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeKind {
    SessionInit,
    SessionReset,
}

#[derive(Debug, Clone, Copy)]
pub struct PendingHandshake {
    pub kind: HandshakeKind,
    pub origin: ResetOrigin,
    pub id: ARID,
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Decode(#[from] dcbor::Error),
    #[error("message expired")]
    Expired,
    #[error("invalid payload")]
    InvalidPayload,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("missing session for {0}")]
    MissingSession(XID),
    #[error("unknown peer {0}")]
    UnknownPeer(XID),
    #[error("session init collision")]
    SessionInitCollision,
    #[error("session reset")]
    SessionReset,
    #[error("timeout")]
    Timeout,
    #[error("send failed")]
    SendFailed,
    #[error("nack {0:?}")]
    Nack(Nack),
    #[error("cancelled")]
    Cancelled,
}

pub trait QlPeer {
    fn encapsulation_pub_key(&self) -> &EncapsulationPublicKey;
    fn signing_pub_key(&self) -> &SigningPublicKey;
    fn session(&self) -> Option<SymmetricKey>;
    fn store_session(&self, key: SymmetricKey);
    fn pending_handshake(&self) -> Option<PendingHandshake>;
    fn set_pending_handshake(&self, handshake: Option<PendingHandshake>);
}

pub trait QlPlatform {
    fn lookup_peer(&self, peer: XID) -> Option<&dyn QlPeer>;
    fn lookup_peer_or_fail(&self, peer: XID) -> Result<&dyn QlPeer, RuntimeError> {
        self.lookup_peer(peer)
            .ok_or_else(|| RuntimeError::UnknownPeer(peer))
    }

    fn encapsulation_private_key(&self) -> EncapsulationPrivateKey;
    fn encapsulation_public_key(&self) -> EncapsulationPublicKey;
    fn signing_key(&self) -> &SigningPublicKey;
    fn message_expiration(&self) -> Duration;
    fn signer(&self) -> &dyn Signer;
    fn handle_error(&self, e: RuntimeError);
    fn store_peer(
        &self,
        signing_pub_key: SigningPublicKey,
        encapsulation_pub_key: EncapsulationPublicKey,
        session: SymmetricKey,
    ) -> Result<(), RuntimeError>;

    fn write_message(&self, message: Vec<u8>) -> PlatformFuture<'_, Result<(), RuntimeError>>;
    fn sleep(&self, duration: Duration) -> PlatformFuture<'_, ()>;

    fn xid(&self) -> XID {
        XID::new(self.signing_key())
    }

    fn decapsulate_shared_secret(
        &self,
        ciphertext: &EncapsulationCiphertext,
    ) -> Result<SymmetricKey, RuntimeError> {
        self.encapsulation_private_key()
            .decapsulate_shared_secret(ciphertext)
            .map_err(|_| RuntimeError::InvalidPayload)
    }

    fn decrypt_message(
        &self,
        key: &SymmetricKey,
        header_aad: &[u8],
        payload: &EncryptedMessage,
    ) -> Result<CBOR, RuntimeError> {
        if payload.aad() != header_aad {
            return Err(RuntimeError::InvalidPayload);
        }
        let plaintext = key
            .decrypt(payload)
            .map_err(|_| RuntimeError::InvalidPayload)?;
        Ok(CBOR::try_from_data(plaintext)?)
    }
}

#[derive(Debug, Clone)]
pub struct RequestConfig {
    pub timeout: Option<Duration>,
}

impl Default for RequestConfig {
    fn default() -> Self {
        Self { timeout: None }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeConfig {
    pub default_timeout: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct ReplyToken {
    pub id: ARID,
    pub recipient: XID,
}

#[derive(Debug, Clone)]
pub struct DecryptedMessage {
    pub header: QlHeader,
    pub payload: QlPayload,
}

#[derive(Debug)]
pub struct InboundRequest {
    pub message: DecryptedMessage,
    pub respond_to: Responder,
}

#[derive(Debug)]
pub struct InboundEvent {
    pub message: DecryptedMessage,
}

#[derive(Debug)]
pub enum HandlerEvent {
    Request(InboundRequest),
    Event(InboundEvent),
}

#[derive(Debug, Clone)]
pub struct Responder {
    id: ARID,
    recipient: XID,
    tx: Sender<RuntimeEvent>,
}

impl Responder {
    pub fn respond<R>(self, response: R) -> Result<(), RuntimeError>
    where
        R: QlCodec,
    {
        self.respond_raw(response.into())
    }

    pub fn respond_raw(self, payload: CBOR) -> Result<(), RuntimeError> {
        self.tx
            .send_blocking(RuntimeEvent::SendResponse {
                id: self.id,
                recipient: self.recipient,
                payload,
                kind: MessageKind::Response,
            })
            .map_err(|_| RuntimeError::Cancelled)
    }

    pub fn respond_nack(self, reason: Nack) -> Result<(), RuntimeError> {
        self.tx
            .send_blocking(RuntimeEvent::SendResponse {
                id: self.id,
                recipient: self.recipient,
                payload: CBOR::from(reason),
                kind: MessageKind::Nack,
            })
            .map_err(|_| RuntimeError::Cancelled)
    }

    pub fn token(&self) -> ReplyToken {
        ReplyToken {
            id: self.id,
            recipient: self.recipient,
        }
    }
}

#[derive(Debug)]
pub struct HandlerStream {
    rx: Receiver<HandlerEvent>,
}

impl HandlerStream {
    pub async fn next(&mut self) -> Result<HandlerEvent, RuntimeError> {
        self.rx.recv().await.map_err(|_| RuntimeError::Cancelled)
    }
}

impl futures_lite::Stream for HandlerStream {
    type Item = Result<HandlerEvent, RuntimeError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let rx = unsafe { self.as_mut().map_unchecked_mut(|s| &mut s.rx) };
        match rx.poll_next(cx) {
            Poll::Ready(Some(event)) => Poll::Ready(Some(Ok(event))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug)]
struct PendingEntry {
    tx: oneshot::Sender<Result<CBOR, RuntimeError>>,
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

enum RuntimeEvent {
    SendRequest {
        id: ARID,
        recipient: XID,
        message_id: u64,
        payload: CBOR,
        respond_to: oneshot::Sender<Result<CBOR, RuntimeError>>,
        config: RequestConfig,
    },
    SendEvent {
        recipient: XID,
        message_id: u64,
        payload: CBOR,
    },
    SendResponse {
        id: ARID,
        recipient: XID,
        payload: CBOR,
        kind: MessageKind,
    },
    SendPairing {
        recipient_signing_key: SigningPublicKey,
        recipient_encapsulation_key: EncapsulationPublicKey,
    },
    Incoming {
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct RuntimeHandle {
    tx: Sender<RuntimeEvent>,
}

pub struct Response<T> {
    rx: oneshot::Receiver<Result<CBOR, RuntimeError>>,
    _type: std::marker::PhantomData<fn() -> T>,
}

impl<T> Future for Response<T>
where
    T: QlCodec,
{
    type Output = Result<T, RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        pin!(&mut self.rx).poll(cx).map(|result| {
            let result = result.unwrap_or(Err(RuntimeError::Cancelled));
            match result {
                Ok(payload) => Ok(T::try_from(payload)?),
                Err(error) => Err(error),
            }
        })
    }
}

impl RuntimeHandle {
    pub fn request<M>(
        &self,
        message: M,
        recipient: XID,
        config: RequestConfig,
    ) -> Response<M::Response>
    where
        M: RequestResponse,
    {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send_blocking(RuntimeEvent::SendRequest {
            id: ARID::new(),
            recipient,
            message_id: M::ID,
            payload: message.into(),
            respond_to: tx,
            config,
        });
        Response {
            rx,
            _type: Default::default(),
        }
    }

    pub fn send_event<M>(&self, message: M, recipient: XID) -> Result<(), RuntimeError>
    where
        M: Event,
    {
        self.tx
            .send_blocking(RuntimeEvent::SendEvent {
                recipient,
                message_id: M::ID,
                payload: message.into(),
            })
            .map_err(|_| RuntimeError::Cancelled)
    }

    pub fn send_pairing_request(
        &self,
        recipient_signing_key: SigningPublicKey,
        recipient_encapsulation_key: EncapsulationPublicKey,
    ) -> Result<(), RuntimeError> {
        self.tx
            .send_blocking(RuntimeEvent::SendPairing {
                recipient_signing_key,
                recipient_encapsulation_key,
            })
            .map_err(|_| RuntimeError::Cancelled)
    }

    pub fn send_incoming(&self, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        self.tx
            .send_blocking(RuntimeEvent::Incoming { bytes })
            .map_err(|_| RuntimeError::Cancelled)
    }
}

pub struct Runtime<P> {
    platform: P,
    rx: Receiver<RuntimeEvent>,
    tx: WeakSender<RuntimeEvent>,
    config: RuntimeConfig,
    incoming: Sender<HandlerEvent>,
}

struct RuntimeState {
    pending: HashMap<ARID, PendingEntry>,
    timeouts: BinaryHeap<Reverse<TimeoutEntry>>,
    outbound: VecDeque<OutboundBytes>,
    in_flight: Option<InFlightWrite>,
}

struct OutboundBytes {
    id: Option<ARID>,
    bytes: Vec<u8>,
}

struct InFlightWrite {
    id: Option<ARID>,
    future: PlatformFuture<'static, Result<(), RuntimeError>>,
}

enum LoopStep {
    Event(Result<RuntimeEvent, async_channel::RecvError>),
    WriteDone {
        id: Option<ARID>,
        result: Result<(), RuntimeError>,
    },
    Timeout,
}

impl<P> Runtime<P>
where
    P: QlPlatform,
{
    pub fn new(platform: P, config: RuntimeConfig) -> (Self, RuntimeHandle, HandlerStream) {
        let (tx, rx) = async_channel::unbounded();
        let (incoming_tx, incoming_rx) = async_channel::unbounded();
        (
            Self {
                platform,
                rx,
                tx: tx.downgrade(),
                config,
                incoming: incoming_tx,
            },
            RuntimeHandle { tx },
            HandlerStream { rx: incoming_rx },
        )
    }

    pub async fn run<'a>(&'a mut self) {
        let mut state = RuntimeState {
            pending: HashMap::new(),
            timeouts: BinaryHeap::new(),
            outbound: VecDeque::new(),
            in_flight: None,
        };
        loop {
            Self::process_timeouts(&mut state.pending, &mut state.timeouts);

            if state.in_flight.is_none() {
                if let Some(message) = state.outbound.pop_front() {
                    let future = self.platform.write_message(message.bytes);
                    state.in_flight = Some(InFlightWrite {
                        id: message.id,
                        future: unsafe {
                            std::mem::transmute::<_, PlatformFuture<'static, _>>(future)
                        },
                    });
                }
            }

            let step = {
                let recv_future = self.rx.recv();
                futures_lite::pin!(recv_future);

                let mut sleep_future = Self::next_timeout_sleep(&state.timeouts)
                    .map(|duration| self.platform.sleep(duration));

                futures_lite::future::poll_fn(|cx| {
                    if let Some(in_flight) = state.in_flight.as_mut() {
                        if let Poll::Ready(result) = in_flight.future.as_mut().poll(cx) {
                            return Poll::Ready(LoopStep::WriteDone {
                                id: in_flight.id,
                                result,
                            });
                        }
                    }

                    if let Some(sleep_future) = sleep_future.as_mut() {
                        if let Poll::Ready(_result) = sleep_future.as_mut().poll(cx) {
                            return Poll::Ready(LoopStep::Timeout);
                        }
                    }

                    match recv_future.as_mut().poll(cx) {
                        Poll::Ready(event) => Poll::Ready(LoopStep::Event(event)),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await
            };

            match step {
                LoopStep::Event(Ok(event)) => match event {
                    RuntimeEvent::SendRequest {
                        id,
                        recipient,
                        message_id,
                        payload,
                        respond_to,
                        config,
                    } => {
                        let effective_timeout =
                            config.timeout.unwrap_or(self.config.default_timeout);
                        if effective_timeout.is_zero() {
                            let _ = respond_to.send(Err(RuntimeError::Timeout));
                            continue;
                        }
                        let deadline = Instant::now() + effective_timeout;
                        let ql_payload = QlPayload {
                            message_id,
                            payload,
                        };
                        match encrypt_payload_for_recipient(
                            &self.platform,
                            recipient,
                            MessageKind::Request,
                            id,
                            ql_payload.into(),
                        ) {
                            Ok((header, encrypted)) => {
                                state.pending.insert(id, PendingEntry { tx: respond_to });
                                state.timeouts.push(Reverse(TimeoutEntry { deadline, id }));
                                let bytes = encode_ql_message(header, encrypted);
                                state.outbound.push_back(OutboundBytes {
                                    id: Some(id),
                                    bytes,
                                });
                            }
                            Err(error) => {
                                let _ = state.pending.remove(&id);
                                let _ = respond_to.send(Err(error));
                            }
                        }
                    }
                    RuntimeEvent::SendEvent {
                        recipient,
                        message_id,
                        payload,
                    } => {
                        let ql_payload = QlPayload {
                            message_id,
                            payload,
                        };
                        match encrypt_payload_for_recipient(
                            &self.platform,
                            recipient,
                            MessageKind::Event,
                            ARID::new(),
                            ql_payload.into(),
                        ) {
                            Ok((header, encrypted)) => {
                                let bytes = encode_ql_message(header, encrypted);
                                state.outbound.push_back(OutboundBytes { id: None, bytes });
                            }
                            Err(error) => self.platform.handle_error(error),
                        }
                    }
                    RuntimeEvent::SendResponse {
                        id,
                        recipient,
                        payload,
                        kind,
                    } => match encrypt_response(&self.platform, recipient, id, payload, kind) {
                        Ok((header, encrypted)) => {
                            let bytes = encode_ql_message(header, encrypted);
                            state.outbound.push_back(OutboundBytes { id: None, bytes });
                        }
                        Err(error) => self.platform.handle_error(error),
                    },
                    RuntimeEvent::SendPairing {
                        recipient_signing_key,
                        recipient_encapsulation_key,
                    } => {
                        match encrypt_pairing_request(
                            &self.platform,
                            &recipient_signing_key,
                            &recipient_encapsulation_key,
                        ) {
                            Ok((header, encrypted)) => {
                                let bytes = encode_ql_message(header, encrypted);
                                state.outbound.push_back(OutboundBytes { id: None, bytes });
                            }
                            Err(error) => self.platform.handle_error(error),
                        }
                    }
                    RuntimeEvent::Incoming { bytes } => {
                        self.handle_incoming_bytes(&mut state, bytes);
                    }
                },
                LoopStep::Event(Err(_)) => break,
                LoopStep::WriteDone { id, result } => {
                    state.in_flight = None;
                    if let Err(error) = result {
                        if let Some(id) = id {
                            if let Some(entry) = state.pending.remove(&id) {
                                let _ = entry.tx.send(Err(error));
                            }
                        }
                    }
                }
                LoopStep::Timeout => {
                    Self::process_timeouts(&mut state.pending, &mut state.timeouts);
                }
            }
        }
    }

    fn handle_incoming_bytes(&mut self, state: &mut RuntimeState, bytes: Vec<u8>) {
        let message = match decode_ql_message(&bytes) {
            Ok(message) => message,
            Err(context) => {
                if let Some(header) = context.header {
                    if header.kind == MessageKind::Response || header.kind == MessageKind::Nack {
                        if let Some(entry) = state.pending.remove(&header.id) {
                            let _ = entry.tx.send(Err(RuntimeError::Decode(match context.error {
                                DecodeError::Cbor(error) => error,
                            })));
                        }
                    }
                }
                return;
            }
        };

        if message.header.kind == MessageKind::Pairing {
            if let Ok((payload, session_key)) =
                decrypt_pairing_payload(&self.platform, &message.header, &message.payload)
            {
                let _ = self.platform.store_peer(
                    payload.signing_pub_key,
                    payload.encapsulation_pub_key,
                    session_key,
                );
            }
            return;
        }

        if message.header.kind == MessageKind::Response || message.header.kind == MessageKind::Nack
        {
            self.handle_response_message(state, message);
            return;
        }

        if let Err(error) = verify_header(&self.platform, &message.header) {
            self.platform.handle_error(error);
            return;
        }

        match message.header.kind {
            MessageKind::Request => {
                let payload =
                    match extract_payload(&self.platform, &message.header, message.payload) {
                        Ok(payload) => payload,
                        Err(error) => {
                            if matches!(
                                error,
                                RuntimeError::InvalidPayload | RuntimeError::MissingSession(_)
                            ) {
                                let _ = self.send_session_reset(state, message.header.sender);
                            }
                            if matches!(error, RuntimeError::Decode(_)) {
                                let _ = self.send_nack(
                                    state,
                                    message.header.sender,
                                    message.header.id,
                                    Nack::InvalidPayload,
                                );
                            }
                            return;
                        }
                    };
                let responder = Responder {
                    id: message.header.id,
                    recipient: message.header.sender,
                    tx: self.tx.upgrade().unwrap(),
                };
                let _ = self
                    .incoming
                    .send_blocking(HandlerEvent::Request(InboundRequest {
                        message: DecryptedMessage {
                            header: message.header,
                            payload,
                        },
                        respond_to: responder,
                    }));
            }
            MessageKind::Event => {
                let payload =
                    match extract_payload(&self.platform, &message.header, message.payload) {
                        Ok(payload) => payload,
                        Err(error) => {
                            if matches!(
                                error,
                                RuntimeError::InvalidPayload | RuntimeError::MissingSession(_)
                            ) {
                                let _ = self.send_session_reset(state, message.header.sender);
                            }
                            return;
                        }
                    };
                let _ = self
                    .incoming
                    .send_blocking(HandlerEvent::Event(InboundEvent {
                        message: DecryptedMessage {
                            header: message.header,
                            payload,
                        },
                    }));
            }
            MessageKind::SessionReset => {
                let _ = extract_reset_payload(&self.platform, &message.header, message.payload);
            }
            MessageKind::Pairing | MessageKind::Response | MessageKind::Nack => {}
        }
    }

    fn handle_response_message(&mut self, state: &mut RuntimeState, message: QlMessage) {
        let header = message.header.clone();
        let Some(entry) = state.pending.remove(&header.id) else {
            return;
        };
        if let Err(error) = verify_header(&self.platform, &header) {
            let _ = entry.tx.send(Err(error));
            return;
        }
        let peer = match self.platform.lookup_peer_or_fail(header.sender) {
            Ok(peer) => peer,
            Err(error) => {
                let _ = entry.tx.send(Err(error));
                return;
            }
        };
        let session_key = match session_key_for_header(&self.platform, peer, &header) {
            Ok(key) => key,
            Err(error) => {
                let _ = entry.tx.send(Err(error));
                return;
            }
        };
        let decrypted =
            match self
                .platform
                .decrypt_message(&session_key, &header.aad_data(), &message.payload)
            {
                Ok(payload) => payload,
                Err(error) => {
                    let _ = entry.tx.send(Err(error));
                    return;
                }
            };
        peer.set_pending_handshake(None);
        if header.kind == MessageKind::Nack {
            let nack = Nack::try_from(decrypted).unwrap_or(Nack::Unknown);
            let _ = entry.tx.send(Err(RuntimeError::Nack(nack)));
        } else {
            let _ = entry.tx.send(Ok(decrypted));
        }
    }

    fn send_session_reset(
        &mut self,
        state: &mut RuntimeState,
        recipient: XID,
    ) -> Result<(), RuntimeError> {
        let peer = self.platform.lookup_peer_or_fail(recipient)?;
        let recipient_key = peer.encapsulation_pub_key();
        let (session_key, kem_ct) = recipient_key.encapsulate_new_shared_secret();
        peer.store_session(session_key.clone());
        let id = ARID::new();
        peer.set_pending_handshake(Some(PendingHandshake {
            kind: HandshakeKind::SessionReset,
            origin: ResetOrigin::Local,
            id,
        }));

        let valid_until = now_secs().saturating_add(self.platform.message_expiration().as_secs());
        let header_unsigned = QlHeader {
            kind: MessageKind::SessionReset,
            id,
            sender: self.platform.xid(),
            recipient,
            valid_until,
            kem_ct: Some(kem_ct.clone()),
            signature: None,
        };
        let aad = header_unsigned.aad_data();
        let payload_bytes = CBOR::null().to_cbor_data();
        let encrypted = session_key.encrypt(payload_bytes, Some(aad), None::<Nonce>);
        let signature = sign_reset_header(self.platform.signer(), &header_unsigned);
        let header = QlHeader {
            signature,
            ..header_unsigned
        };
        let bytes = encode_ql_message(header, encrypted);
        state.outbound.push_back(OutboundBytes { id: None, bytes });
        Ok(())
    }

    fn send_nack(
        &mut self,
        state: &mut RuntimeState,
        recipient: XID,
        id: ARID,
        reason: Nack,
    ) -> Result<(), RuntimeError> {
        let (header, encrypted) = match encrypt_response(
            &self.platform,
            recipient,
            id,
            CBOR::from(reason),
            MessageKind::Nack,
        ) {
            Ok(result) => result,
            Err(RuntimeError::MissingSession(_)) => return Ok(()),
            Err(error) => return Err(error),
        };
        let bytes = encode_ql_message(header, encrypted);
        state.outbound.push_back(OutboundBytes { id: None, bytes });
        Ok(())
    }

    fn process_timeouts(
        pending: &mut HashMap<ARID, PendingEntry>,
        timeouts: &mut BinaryHeap<Reverse<TimeoutEntry>>,
    ) {
        let now = Instant::now();
        while let Some(Reverse(entry)) = timeouts.peek().cloned() {
            if entry.deadline > now {
                break;
            }
            timeouts.pop();
            if let Some(pending) = pending.remove(&entry.id) {
                let _ = pending.tx.send(Err(RuntimeError::Timeout));
            }
        }
    }

    fn next_timeout_sleep(timeouts: &BinaryHeap<Reverse<TimeoutEntry>>) -> Option<Duration> {
        let Reverse(entry) = timeouts.peek()?;
        let now = Instant::now();
        Some(entry.deadline.saturating_duration_since(now))
    }
}
