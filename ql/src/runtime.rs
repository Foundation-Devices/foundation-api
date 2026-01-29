use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, HashMap, VecDeque},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_channel::{Receiver, Sender, WeakSender};
use bc_components::{EncapsulationPublicKey, Nonce, SigningPublicKey, ARID, XID};
use dcbor::CBOR;

use crate::{
    encrypt::*,
    handle::RuntimeHandle,
    platform::{
        HandshakeKind, PeerStatus, PendingHandshake, PlatformFuture, QlPeer, QlPlatform,
        QlPlatformExt, ResetOrigin,
    },
    wire::*,
    QlCodec, QlError,
};

#[derive(Debug, Clone, Default)]
pub struct RequestConfig {
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
pub struct KeepAliveConfig {
    pub interval: Duration,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeConfig {
    pub default_timeout: Duration,
    pub message_expiration: Duration,
    pub keep_alive: Option<KeepAliveConfig>,
}

#[derive(Debug)]
pub enum HandlerEvent {
    Request(InboundRequest),
    Event(InboundEvent),
}

#[derive(Debug, Clone)]
pub struct DecryptedMessage {
    pub header: QlDetails,
    pub payload: CBOR,
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

#[derive(Debug, Clone)]
pub struct Responder {
    id: ARID,
    recipient: XID,
    tx: Sender<RuntimeEvent>,
}

impl Responder {
    pub fn respond<R>(self, response: R) -> Result<(), QlError>
    where
        R: QlCodec,
    {
        self.tx
            .send_blocking(RuntimeEvent::SendResponse {
                id: self.id,
                recipient: self.recipient,
                payload: response.into(),
                kind: MessageKind::Response,
            })
            .map_err(|_| QlError::Cancelled)
    }

    pub fn respond_nack(self, reason: Nack) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeEvent::SendResponse {
                id: self.id,
                recipient: self.recipient,
                payload: CBOR::from(reason),
                kind: MessageKind::Nack,
            })
            .map_err(|_| QlError::Cancelled)
    }
}

#[derive(Debug)]
pub struct HandlerStream {
    rx: Receiver<HandlerEvent>,
}

impl HandlerStream {
    pub async fn next(&mut self) -> Result<HandlerEvent, QlError> {
        self.rx.recv().await.map_err(|_| QlError::Cancelled)
    }
}

impl futures_lite::Stream for HandlerStream {
    type Item = Result<HandlerEvent, QlError>;

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
    tx: oneshot::Sender<Result<CBOR, QlError>>,
    recipient: XID,
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

pub(crate) enum RuntimeEvent {
    SendRequest {
        id: ARID,
        recipient: XID,
        message_id: u64,
        payload: CBOR,
        respond_to: oneshot::Sender<Result<CBOR, QlError>>,
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
    keepalive: Vec<PeerKeepAlive>,
}

struct OutboundBytes {
    id: Option<ARID>,
    bytes: Vec<u8>,
}

struct InFlightWrite<'a> {
    id: Option<ARID>,
    future: PlatformFuture<'a, Result<(), QlError>>,
}

#[derive(Debug, Clone, Copy)]
struct PendingHeartbeat {
    id: ARID,
    deadline: Instant,
}

#[derive(Debug)]
struct PeerKeepAlive {
    peer: XID,
    last_activity: Option<Instant>,
    next_heartbeat_at: Option<Instant>,
    pending_heartbeat: Option<PendingHeartbeat>,
    status: Option<PeerStatus>,
}

impl PeerKeepAlive {
    fn new(peer: XID) -> Self {
        Self {
            peer,
            last_activity: None,
            next_heartbeat_at: None,
            pending_heartbeat: None,
            status: None,
        }
    }
}

enum LoopStep {
    Event(RuntimeEvent),
    WriteDone {
        id: Option<ARID>,
        result: Result<(), QlError>,
    },
    Timeout,
    Quit,
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
            keepalive: Vec::new(),
        };
        let mut in_flight: Option<InFlightWrite<'_>> = None;
        loop {
            self.process_request_timeouts(&mut state);
            self.process_keepalives(&mut state);

            if in_flight.is_none() {
                if let Some(message) = state.outbound.pop_front() {
                    in_flight = Some(InFlightWrite {
                        id: message.id,
                        future: self.platform.write_message(message.bytes),
                    });
                }
            }

            let step = {
                let recv_future = self.rx.recv();
                futures_lite::pin!(recv_future);

                let next_request = Self::next_timeout_sleep(&state.timeouts);
                let next_keepalive = Self::next_keepalive_sleep(&state.keepalive);
                let sleep_duration = min_duration(&[next_request, next_keepalive]);
                let mut sleep_future = sleep_duration.map(|duration| self.platform.sleep(duration));

                futures_lite::future::poll_fn(|cx| {
                    if let Some(in_flight) = in_flight.as_mut() {
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
                        Poll::Ready(Ok(event)) => Poll::Ready(LoopStep::Event(event)),
                        Poll::Ready(Err(_)) => Poll::Ready(LoopStep::Quit),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await
            };

            match step {
                LoopStep::Quit => break,
                LoopStep::Event(event) => match event {
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
                            let _ = respond_to.send(Err(QlError::Timeout));
                            continue;
                        }
                        let deadline = Instant::now() + effective_timeout;
                        let ql_payload = payload;
                        match encrypt_payload_for_recipient(
                            &self.platform,
                            recipient,
                            MessageKind::Request,
                            id,
                            message_id,
                            ql_payload,
                            self.config.message_expiration,
                        ) {
                            Ok((header, encrypted)) => {
                                if header.kem_ct.is_some() {
                                    self.mark_connecting(&mut state, recipient);
                                }
                                state.pending.insert(
                                    id,
                                    PendingEntry {
                                        tx: respond_to,
                                        recipient,
                                    },
                                );
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
                        let ql_payload = payload;
                        match encrypt_payload_for_recipient(
                            &self.platform,
                            recipient,
                            MessageKind::Event,
                            ARID::new(),
                            message_id,
                            ql_payload,
                            self.config.message_expiration,
                        ) {
                            Ok((header, encrypted)) => {
                                if header.kem_ct.is_some() {
                                    self.mark_connecting(&mut state, recipient);
                                }
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
                    } => match encrypt_response(
                        &self.platform,
                        recipient,
                        id,
                        payload,
                        kind,
                        self.config.message_expiration,
                    ) {
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
                        let recipient = XID::new(&recipient_signing_key);
                        let (header, encrypted) = encrypt_pairing_request(
                            &self.platform,
                            &recipient_signing_key,
                            &recipient_encapsulation_key,
                            self.config.message_expiration,
                        );
                        let bytes = encode_ql_message(header, encrypted);
                        state.outbound.push_back(OutboundBytes { id: None, bytes });
                        self.mark_connecting(&mut state, recipient);
                    }
                    RuntimeEvent::Incoming { bytes } => {
                        self.handle_incoming_bytes(&mut state, bytes);
                    }
                },
                LoopStep::WriteDone { id, result } => {
                    in_flight = None;
                    if let Err(error) = result {
                        if let Some(id) = id {
                            if let Some(entry) = state.pending.remove(&id) {
                                let _ = entry.tx.send(Err(error));
                            }
                        }
                    }
                }
                LoopStep::Timeout => {
                    self.process_request_timeouts(&mut state);
                    self.process_keepalives(&mut state);
                }
            }
        }
    }

    fn handle_incoming_bytes(&self, state: &mut RuntimeState, bytes: Vec<u8>) {
        let message = match decode_ql_message(&bytes) {
            Ok(message) => message,
            Err(_context) => {
                return;
            }
        };
        let QlMessage { header, payload } = message;

        if header.kind == MessageKind::Pairing {
            if let Ok((payload, session_key)) =
                decrypt_pairing_payload(&self.platform, &header, &payload)
            {
                self.platform.store_peer(
                    payload.signing_pub_key,
                    payload.encapsulation_pub_key,
                    session_key,
                );
                self.record_activity(state, header.sender);
            }
            return;
        }

        if header.kind == MessageKind::SessionReset {
            let sender = header.sender;
            match extract_reset_payload(&self.platform, header, payload) {
                Ok(()) => {
                    self.mark_connecting(state, sender);
                    self.record_activity(state, sender);
                    let reset_entries = state
                        .pending
                        .extract_if(|_id, entry| entry.recipient == sender);
                    for (_id, entry) in reset_entries {
                        let _ = entry.tx.send(Err(QlError::SessionReset));
                    }
                }
                Err(error) => self.platform.handle_error(error),
            }
            return;
        }

        let sender = header.sender;
        let has_kem_ct = header.kem_ct.is_some();
        let kind = header.kind;
        let (details, payload) = match extract_envelope(&self.platform, header, payload) {
            Ok(result) => result,
            Err(QlError::InvalidPayload) | Err(QlError::MissingSession(_)) => {
                let _ = self.send_session_reset(state, sender);
                return;
            }
            Err(e) => {
                self.platform.handle_error(e);
                return;
            }
        };

        match kind {
            MessageKind::Request | MessageKind::Event => {
                if has_kem_ct {
                    self.mark_connecting(state, sender);
                }
                self.record_activity(state, sender);
                self.dispatch_decrypted_message(details, payload);
            }
            MessageKind::Heartbeat => {
                self.handle_heartbeat_message(state, details, payload, has_kem_ct);
            }
            MessageKind::Response | MessageKind::Nack => {
                self.handle_response_message(state, details, payload, has_kem_ct);
            }
            MessageKind::Pairing | MessageKind::SessionReset => {}
        }
    }

    fn handle_response_message(
        &self,
        state: &mut RuntimeState,
        details: QlDetails,
        payload: CBOR,
        has_kem_ct: bool,
    ) {
        let Some(entry) = state.pending.remove(&details.id) else {
            return;
        };
        if has_kem_ct {
            self.mark_connecting(state, details.sender);
        }
        self.record_activity(state, details.sender);
        if details.kind == MessageKind::Nack {
            let nack = Nack::from(payload);
            let _ = entry.tx.send(Err(QlError::Nack(nack)));
        } else {
            let _ = entry.tx.send(Ok(payload));
        }
    }

    fn handle_heartbeat_message(
        &self,
        state: &mut RuntimeState,
        details: QlDetails,
        payload: CBOR,
        has_kem_ct: bool,
    ) {
        if !payload.is_null() {
            let _ = self.send_session_reset(state, details.sender);
            return;
        }
        let should_respond = !self.is_pending_heartbeat(state, details.sender, details.id);
        if has_kem_ct {
            self.mark_connecting(state, details.sender);
        }
        self.record_activity(state, details.sender);
        if should_respond {
            if let Err(error) = self.send_heartbeat_message(state, details.sender, details.id) {
                self.platform.handle_error(error);
            }
        }
    }

    fn dispatch_decrypted_message(&self, details: QlDetails, payload: CBOR) {
        match details.kind {
            MessageKind::Request => {
                let responder = Responder {
                    id: details.id,
                    recipient: details.sender,
                    tx: self.tx.upgrade().unwrap(),
                };
                let _ = self
                    .incoming
                    .send_blocking(HandlerEvent::Request(InboundRequest {
                        message: DecryptedMessage {
                            header: details,
                            payload,
                        },
                        respond_to: responder,
                    }));
            }
            MessageKind::Event => {
                let _ = self
                    .incoming
                    .send_blocking(HandlerEvent::Event(InboundEvent {
                        message: DecryptedMessage {
                            header: details,
                            payload,
                        },
                    }));
            }
            _ => {}
        }
    }

    fn send_session_reset(&self, state: &mut RuntimeState, recipient: XID) -> Result<(), QlError> {
        let (session_key, kem_ct, id) = {
            let peer = self.platform.lookup_peer_or_fail(recipient)?;
            let recipient_key = peer.encapsulation_pub_key().clone();
            let (session_key, kem_ct) = recipient_key.encapsulate_new_shared_secret();
            let id = ARID::new();
            peer.store_session(session_key.clone());
            peer.set_pending_handshake(Some(PendingHandshake {
                kind: HandshakeKind::SessionReset,
                origin: ResetOrigin::Local,
                id,
            }));
            (session_key, kem_ct, id)
        };
        self.mark_connecting(state, recipient);

        let valid_until = now_secs().saturating_add(self.config.message_expiration.as_secs());
        let header_unsigned = QlHeader {
            kind: MessageKind::SessionReset,
            sender: self.platform.xid(),
            recipient,
            kem_ct: Some(kem_ct.clone()),
            signature: None,
        };
        let envelope = QlEnvelope {
            id,
            valid_until,
            message_id: 0,
            payload: CBOR::null(),
        };
        let aad = header_unsigned.aad_data();
        let payload_bytes = CBOR::from(envelope).to_cbor_data();
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
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        id: ARID,
        reason: Nack,
    ) -> Result<(), QlError> {
        let (header, encrypted) = encrypt_response(
            &self.platform,
            recipient,
            id,
            CBOR::from(reason),
            MessageKind::Nack,
            self.config.message_expiration,
        )?;
        let bytes = encode_ql_message(header, encrypted);
        state.outbound.push_back(OutboundBytes { id: None, bytes });
        Ok(())
    }

    fn keep_alive_config(&self) -> Option<KeepAliveConfig> {
        self.config
            .keep_alive
            .filter(|config| !config.interval.is_zero() && !config.timeout.is_zero())
    }

    fn update_peer_status(&self, entry: &mut PeerKeepAlive, peer: XID, status: PeerStatus) {
        if entry.status != Some(status) {
            self.platform.handle_peer_status(peer, status);
            entry.status = Some(status);
        }
    }

    fn keepalive_entry_mut<'a>(
        &self,
        state: &'a mut RuntimeState,
        peer: XID,
    ) -> &'a mut PeerKeepAlive {
        if let Some(index) = state.keepalive.iter().position(|entry| entry.peer == peer) {
            return &mut state.keepalive[index];
        }
        state.keepalive.push(PeerKeepAlive::new(peer));
        let index = state.keepalive.len() - 1;
        &mut state.keepalive[index]
    }

    fn mark_connecting(&self, state: &mut RuntimeState, peer: XID) {
        let entry = self.keepalive_entry_mut(state, peer);
        entry.pending_heartbeat = None;
        entry.next_heartbeat_at = None;
        self.update_peer_status(entry, peer, PeerStatus::Connecting);
    }

    fn record_activity(&self, state: &mut RuntimeState, peer: XID) {
        let now = Instant::now();
        let entry = self.keepalive_entry_mut(state, peer);
        entry.last_activity = Some(now);
        entry.pending_heartbeat = None;
        self.update_peer_status(entry, peer, PeerStatus::Connected);
        if let Some(config) = self.keep_alive_config() {
            let deadline = now + config.interval;
            entry.next_heartbeat_at = Some(deadline);
        } else {
            entry.next_heartbeat_at = None;
        }
    }

    fn is_pending_heartbeat(&self, state: &RuntimeState, peer: XID, id: ARID) -> bool {
        state
            .keepalive
            .iter()
            .find(|entry| entry.peer == peer)
            .and_then(|entry| entry.pending_heartbeat)
            .map_or(false, |pending| pending.id == id)
    }

    fn send_heartbeat_message(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        id: ARID,
    ) -> Result<bool, QlError> {
        let (header, encrypted) = match encrypt_response(
            &self.platform,
            recipient,
            id,
            CBOR::null(),
            MessageKind::Heartbeat,
            self.config.message_expiration,
        ) {
            Ok(result) => result,
            Err(QlError::MissingSession(_)) => return Ok(false),
            Err(error) => return Err(error),
        };
        let bytes = encode_ql_message(header, encrypted);
        state.outbound.push_back(OutboundBytes { id: None, bytes });
        Ok(true)
    }

    fn process_request_timeouts(&self, state: &mut RuntimeState) {
        let now = Instant::now();
        while let Some(Reverse(entry)) = state.timeouts.peek().cloned() {
            if entry.deadline > now {
                break;
            }
            state.timeouts.pop();
            if let Some(pending) = state.pending.remove(&entry.id) {
                let _ = pending.tx.send(Err(QlError::Timeout));
            }
        }
    }

    fn process_keepalives(&self, state: &mut RuntimeState) {
        let Some(config) = self.keep_alive_config() else {
            return;
        };
        let now = Instant::now();
        let mut send_targets = Vec::new();
        for entry in &mut state.keepalive {
            if let Some(pending) = entry.pending_heartbeat {
                if pending.deadline <= now {
                    entry.pending_heartbeat = None;
                    entry.next_heartbeat_at = None;
                    self.update_peer_status(entry, entry.peer, PeerStatus::Disconnected);
                }
                continue;
            }
            if entry.status != Some(PeerStatus::Connected) {
                continue;
            }
            let Some(deadline) = entry.next_heartbeat_at else {
                continue;
            };
            if deadline <= now {
                entry.next_heartbeat_at = None;
                send_targets.push(entry.peer);
            }
        }

        for peer in send_targets {
            let heartbeat_id = ARID::new();
            let heartbeat_deadline = now + config.timeout;
            let send_result = self.send_heartbeat_message(state, peer, heartbeat_id);
            let entry = self.keepalive_entry_mut(state, peer);
            match send_result {
                Ok(true) => {
                    entry.pending_heartbeat = Some(PendingHeartbeat {
                        id: heartbeat_id,
                        deadline: heartbeat_deadline,
                    });
                    self.update_peer_status(entry, peer, PeerStatus::HeartbeatPending);
                }
                Ok(false) => {}
                Err(error) => {
                    self.platform.handle_error(error);
                }
            }
        }
    }

    fn next_timeout_sleep(timeouts: &BinaryHeap<Reverse<TimeoutEntry>>) -> Option<Duration> {
        let Reverse(entry) = timeouts.peek()?;
        let now = Instant::now();
        Some(entry.deadline.saturating_duration_since(now))
    }

    fn next_keepalive_sleep(entries: &[PeerKeepAlive]) -> Option<Duration> {
        let now = Instant::now();
        let mut next_deadline: Option<Instant> = None;
        for entry in entries {
            if let Some(deadline) = entry.next_heartbeat_at {
                next_deadline = Some(next_deadline.map_or(deadline, |next| next.min(deadline)));
            }
            if let Some(pending) = entry.pending_heartbeat {
                let deadline = pending.deadline;
                next_deadline = Some(next_deadline.map_or(deadline, |next| next.min(deadline)));
            }
        }
        next_deadline.map(|deadline| deadline.saturating_duration_since(now))
    }
}

fn min_duration(durations: &[Option<Duration>]) -> Option<Duration> {
    durations
        .iter()
        .flatten()
        .fold(None, |min, duration| {
            Some(min.map_or(duration, |current: &Duration| current.min(duration)))
        })
        .copied()
}
