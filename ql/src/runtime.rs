use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, HashMap, VecDeque},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_channel::{Receiver, Sender, WeakSender};
use bc_components::{EncapsulationPublicKey, Nonce, SigningPublicKey, XID};
use dcbor::{CBOREncodable, CBOR};

use crate::{
    encrypt::*,
    handle::RuntimeHandle,
    platform::{
        PeerStatus, PendingSession, PlatformFuture, QlPeer, QlPlatform, QlPlatformExt, ResetOrigin,
        SessionKind,
    },
    wire::*,
    MessageId, QlCodec, QlError, RouteId, SessionEpoch,
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
    id: MessageId,
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
    id: MessageId,
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
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
        respond_to: oneshot::Sender<Result<CBOR, QlError>>,
        config: RequestConfig,
    },
    SendEvent {
        recipient: XID,
        route_id: RouteId,
        payload: CBOR,
    },
    SendResponse {
        id: MessageId,
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
    pending: HashMap<MessageId, PendingEntry>,
    timeouts: BinaryHeap<Reverse<TimeoutEntry>>,
    outbound: VecDeque<OutboundBytes>,
    keepalive: Vec<PeerKeepAlive>,
    next_message_id: u64,
}

impl RuntimeState {
    fn next_id(&mut self) -> MessageId {
        let id = self.next_message_id;
        self.next_message_id = id.wrapping_add(1);
        MessageId::new(id)
    }
}

struct OutboundBytes {
    id: Option<MessageId>,
    bytes: Vec<u8>,
}

struct InFlightWrite<'a> {
    id: Option<MessageId>,
    future: PlatformFuture<'a, Result<(), QlError>>,
}

#[derive(Debug, Clone, Copy)]
struct PendingHeartbeat {
    id: MessageId,
    deadline: Instant,
}

#[derive(Debug, Clone, Copy)]
enum HeartbeatState {
    Idle,
    Waiting { next_heartbeat_at: Instant },
    Pending { heartbeat: PendingHeartbeat },
}

#[derive(Debug)]
struct PeerKeepAlive {
    peer: XID,
    last_activity: Option<Instant>,
    heartbeat: HeartbeatState,
    status: PeerStatus,
}

impl PeerKeepAlive {
    fn new(peer: XID) -> Self {
        Self {
            peer,
            last_activity: None,
            heartbeat: HeartbeatState::Idle,
            status: PeerStatus::Disconnected,
        }
    }

    fn pending_heartbeat_id(&self) -> Option<MessageId> {
        match self.heartbeat {
            HeartbeatState::Pending { heartbeat } => Some(heartbeat.id),
            _ => None,
        }
    }
}

enum LoopStep {
    Event(RuntimeEvent),
    WriteDone {
        id: Option<MessageId>,
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
            next_message_id: 1,
        };
        let mut in_flight: Option<InFlightWrite<'_>> = None;
        loop {
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

                let sleep_duration = Self::next_sleep(&state.timeouts, &state.keepalive);
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
                        recipient,
                        route_id,
                        payload,
                        respond_to,
                        config,
                    } => {
                        let id = state.next_id();
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
                            route_id,
                            ql_payload,
                            self.config.message_expiration,
                        ) {
                            Ok(message) => {
                                state.pending.insert(
                                    id,
                                    PendingEntry {
                                        tx: respond_to,
                                        recipient,
                                    },
                                );
                                state.timeouts.push(Reverse(TimeoutEntry { deadline, id }));
                                self.queue_outbound(&mut state, Some(id), message);
                            }
                            Err(error) => {
                                let _ = state.pending.remove(&id);
                                let _ = respond_to.send(Err(error));
                            }
                        }
                    }
                    RuntimeEvent::SendEvent {
                        recipient,
                        route_id,
                        payload,
                    } => {
                        let ql_payload = payload;
                        let id = state.next_id();
                        match encrypt_payload_for_recipient(
                            &self.platform,
                            recipient,
                            MessageKind::Event,
                            id,
                            route_id,
                            ql_payload,
                            self.config.message_expiration,
                        ) {
                            Ok(message) => {
                                self.queue_outbound(&mut state, None, message);
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
                        Ok(message) => {
                            self.queue_outbound(&mut state, None, message);
                        }
                        Err(error) => self.platform.handle_error(error),
                    },
                    RuntimeEvent::SendPairing {
                        recipient_signing_key,
                        recipient_encapsulation_key,
                    } => {
                        let message_id = state.next_id();
                        let message = encrypt_pairing_request(
                            &self.platform,
                            &recipient_signing_key,
                            &recipient_encapsulation_key,
                            message_id,
                            self.config.message_expiration,
                        );
                        self.queue_outbound(&mut state, None, message);
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
        let encrypted = match CBOR::try_from_data(&bytes).and_then(EncryptedMessage::try_from) {
            Ok(message) => message,
            Err(_context) => {
                return;
            }
        };

        let sender = encrypted.header.sender();

        if matches!(&encrypted.header, QlHeader::Pairing { .. }) {
            if let Ok((payload, session_key)) = decrypt_pairing_payload(&self.platform, encrypted) {
                self.platform.store_peer(
                    payload.signing_pub_key,
                    payload.encapsulation_pub_key,
                    session_key,
                    SessionEpoch::new(1),
                );
                self.record_activity(state, sender);
            }
            return;
        }

        if matches!(&encrypted.header, QlHeader::SessionReset { .. }) {
            match extract_reset_payload(&self.platform, encrypted) {
                Ok(()) => {
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

        let message = match extract_envelope(&self.platform, encrypted) {
            Ok(result) => result,
            Err(EnvelopeError::Error(QlError::StaleSession)) => {
                return;
            }
            Err(EnvelopeError::Error(QlError::InvalidPayload))
            | Err(EnvelopeError::Error(QlError::MissingSession(_))) => {
                if let Some(peer) = self.platform.lookup_peer(sender) {
                    // Avoid overriding a peer-initiated reset with a local reset.
                    if let Some(pending) = peer.pending_session() {
                        if pending.kind == SessionKind::SessionReset
                            && pending.origin == ResetOrigin::Peer
                        {
                            return;
                        }
                    }
                }
                let _ = self.send_session_reset(state, sender);
                return;
            }
            Err(EnvelopeError::Nack { nack, id, kind }) => {
                if matches!(kind, MessageKind::Response | MessageKind::Nack) {
                    self.resolve_pending_nack(state, id, nack);
                }
                let _ = self.send_nack(state, sender, id, nack);
                return;
            }
            Err(EnvelopeError::Error(e)) => {
                self.platform.handle_error(e);
                return;
            }
        };

        self.record_activity(state, sender);

        match message.header.kind {
            MessageKind::Request | MessageKind::Event => {
                self.dispatch_decrypted_message(message);
            }
            MessageKind::Heartbeat => {
                self.handle_heartbeat_message(state, message);
            }
            MessageKind::Response | MessageKind::Nack => {
                self.handle_response_message(state, message);
            }
        }
    }

    fn handle_response_message(
        &self,
        state: &mut RuntimeState,
        DecryptedMessage { header, payload }: DecryptedMessage,
    ) {
        if header.kind == MessageKind::Nack {
            let nack = Nack::from(payload);
            self.resolve_pending_nack(state, header.message_id, nack);
        } else {
            let Some(entry) = state.pending.remove(&header.message_id) else {
                return;
            };
            let _ = entry.tx.send(Ok(payload));
        }
    }

    fn resolve_pending_nack(&self, state: &mut RuntimeState, id: MessageId, nack: Nack) {
        if let Some(entry) = state.pending.remove(&id) {
            let _ = entry.tx.send(Err(QlError::Nack { id, nack }));
        }
    }

    fn handle_heartbeat_message(
        &self,
        state: &mut RuntimeState,
        DecryptedMessage { header, payload }: DecryptedMessage,
    ) {
        if !payload.is_null() {
            let _ = self.send_session_reset(state, header.sender);
            return;
        }

        let is_response = state
            .keepalive
            .iter()
            .find(|entry| entry.peer == header.sender)
            .and_then(|entry| entry.pending_heartbeat_id())
            .map_or(false, |id| id == header.message_id);

        if !is_response {
            if let Err(error) = self.send_heartbeat_message(state, header.sender, header.message_id)
            {
                self.platform.handle_error(error);
            }
        }
    }

    fn dispatch_decrypted_message(&self, message: DecryptedMessage) {
        match message.header.kind {
            MessageKind::Request => {
                let responder = Responder {
                    id: message.header.message_id,
                    recipient: message.header.sender,
                    tx: self.tx.upgrade().unwrap(),
                };
                let _ = self
                    .incoming
                    .send_blocking(HandlerEvent::Request(InboundRequest {
                        message,
                        respond_to: responder,
                    }));
            }
            MessageKind::Event => {
                let _ = self
                    .incoming
                    .send_blocking(HandlerEvent::Event(InboundEvent { message }));
            }
            _ => {}
        }
    }

    fn queue_outbound(
        &self,
        state: &mut RuntimeState,
        id: Option<MessageId>,
        message: EncryptedMessage,
    ) {
        if message.header.has_new_session() {
            let recipient = message.header.recipient();
            let entry = self.keepalive_entry_mut(state, recipient);
            entry.heartbeat = HeartbeatState::Idle;
            self.update_peer_status(entry, recipient, PeerStatus::Connecting);
        }
        let bytes = message.to_cbor_data();
        state.outbound.push_back(OutboundBytes { id, bytes });
    }

    fn send_session_reset(&self, state: &mut RuntimeState, recipient: XID) -> Result<(), QlError> {
        let (session_key, kem_ct, id, epoch) = {
            let peer = self.platform.lookup_peer_or_fail(recipient)?;
            let recipient_key = peer.encapsulation_pub_key().clone();
            let (session_key, kem_ct) = recipient_key.encapsulate_new_shared_secret();
            let id = state.next_id();
            let epoch = peer
                .session_epoch()
                .map(SessionEpoch::next)
                .unwrap_or_else(|| SessionEpoch::new(1));
            peer.store_session_key(session_key.clone());
            peer.set_session_epoch(Some(epoch));
            peer.set_pending_session(Some(PendingSession {
                kind: SessionKind::SessionReset,
                origin: ResetOrigin::Local,
                id,
                epoch,
            }));
            (session_key, kem_ct, id, epoch)
        };

        let valid_until = now_secs().saturating_add(self.config.message_expiration.as_secs());
        let aad = QlHeader::session_reset_aad(self.platform.xid(), recipient, &kem_ct);
        let signature = sign_header(self.platform.signer(), &aad);
        let header = QlHeader::SessionReset {
            sender: self.platform.xid(),
            recipient,
            kem_ct: kem_ct.clone(),
            signature,
        };
        let envelope = SessionPayload {
            message_id: id,
            valid_until,
            session_epoch: epoch,
        };
        let payload_bytes = CBOR::from(envelope).to_cbor_data();
        let encrypted = session_key.encrypt(payload_bytes, Some(aad), None::<Nonce>);
        let message = EncryptedMessage { header, encrypted };
        self.queue_outbound(state, None, message);
        Ok(())
    }

    fn send_nack(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        id: MessageId,
        reason: Nack,
    ) -> Result<(), QlError> {
        let message = encrypt_response(
            &self.platform,
            recipient,
            id,
            CBOR::from(reason),
            MessageKind::Nack,
            self.config.message_expiration,
        )?;
        self.queue_outbound(state, None, message);
        Ok(())
    }

    fn keep_alive_config(&self) -> Option<KeepAliveConfig> {
        self.config
            .keep_alive
            .filter(|config| !config.interval.is_zero() && !config.timeout.is_zero())
    }

    fn update_peer_status(&self, entry: &mut PeerKeepAlive, peer: XID, status: PeerStatus) {
        if entry.status != status {
            self.platform.handle_peer_status(peer, status);
            entry.status = status;
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

    fn record_activity(&self, state: &mut RuntimeState, peer: XID) {
        let now = Instant::now();
        let entry = self.keepalive_entry_mut(state, peer);
        entry.last_activity = Some(now);
        self.update_peer_status(entry, peer, PeerStatus::Connected);
        if let Some(config) = self.keep_alive_config() {
            let deadline = now + config.interval;
            entry.heartbeat = HeartbeatState::Waiting {
                next_heartbeat_at: deadline,
            };
        } else {
            entry.heartbeat = HeartbeatState::Idle;
        }
    }

    fn send_heartbeat_message(
        &self,
        state: &mut RuntimeState,
        recipient: XID,
        id: MessageId,
    ) -> Result<bool, QlError> {
        let message = match encrypt_response(
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
        self.queue_outbound(state, None, message);
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
        let mut index = 0;
        while index < state.keepalive.len() {
            let mut send_peer = None;
            {
                let entry = &mut state.keepalive[index];
                match entry.heartbeat {
                    HeartbeatState::Pending { heartbeat } => {
                        if heartbeat.deadline <= now {
                            entry.heartbeat = HeartbeatState::Idle;
                            self.update_peer_status(entry, entry.peer, PeerStatus::Disconnected);
                        }
                    }
                    HeartbeatState::Waiting { next_heartbeat_at } => {
                        if entry.status == PeerStatus::Connected && next_heartbeat_at <= now {
                            entry.heartbeat = HeartbeatState::Idle;
                            send_peer = Some(entry.peer);
                        }
                    }
                    HeartbeatState::Idle => {}
                }
            }

            if let Some(peer) = send_peer {
                let heartbeat_id = state.next_id();
                let send_result = self.send_heartbeat_message(state, peer, heartbeat_id);
                match send_result {
                    Ok(true) => {
                        let entry = &mut state.keepalive[index];
                        entry.heartbeat = HeartbeatState::Pending {
                            heartbeat: PendingHeartbeat {
                                id: heartbeat_id,
                                deadline: now + config.timeout,
                            },
                        };
                        self.update_peer_status(entry, peer, PeerStatus::HeartbeatPending);
                    }
                    Ok(false) => {}
                    Err(error) => {
                        self.platform.handle_error(error);
                    }
                }
            }

            if state.keepalive[index].status == PeerStatus::Disconnected {
                state.keepalive.swap_remove(index);
            } else {
                index += 1;
            }
        }
    }

    fn next_sleep(
        timeouts: &BinaryHeap<Reverse<TimeoutEntry>>,
        keepalive: &[PeerKeepAlive],
    ) -> Option<Duration> {
        let now = Instant::now();
        let next_request = Self::next_timeout_sleep(now, &timeouts);
        let next_keepalive = Self::next_keepalive_sleep(now, &keepalive);
        min_duration(&[next_request, next_keepalive])
    }

    fn next_timeout_sleep(
        now: Instant,
        timeouts: &BinaryHeap<Reverse<TimeoutEntry>>,
    ) -> Option<Duration> {
        let Reverse(entry) = timeouts.peek()?;
        Some(entry.deadline.saturating_duration_since(now))
    }

    fn next_keepalive_sleep(now: Instant, entries: &[PeerKeepAlive]) -> Option<Duration> {
        let mut next_deadline: Option<Instant> = None;
        for entry in entries {
            let deadline = match entry.heartbeat {
                HeartbeatState::Waiting { next_heartbeat_at } => Some(next_heartbeat_at),
                HeartbeatState::Pending { heartbeat } => Some(heartbeat.deadline),
                HeartbeatState::Idle => None,
            };
            if let Some(deadline) = deadline {
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
