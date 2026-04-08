mod state;
#[cfg(test)]
mod test;

use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    future::Future,
    pin::{pin, Pin},
    task::Poll,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures_lite::future::poll_fn;
use ql_fsm::{FsmTime, QlFsm, QlFsmEvent, SessionWriteId};
use ql_wire::{CloseTarget, PairingToken, StreamCloseCode, StreamId};

use self::state::{DriverState, DriverStreamIo, InboundIo, InboundWriteResult, OutboundIo};
use crate::{
    chunk_slot,
    command::RuntimeCommand,
    handle::{ByteReader, ByteWriter, QlStream},
    platform::{PlatformFuture, QlPlatform, QlTimer},
    QlStreamError, Runtime, RuntimeHandle,
};

impl<P: QlPlatform> Runtime<P> {
    #[allow(clippy::future_not_send)]
    pub async fn run(self) {
        let Self {
            identity,
            platform,
            config,
            rx,
            tx,
        } = self;

        let mut fsm = QlFsm::new(config.fsm, identity, now());
        if let Some(peer) = platform.load_peer().await {
            fsm.bind_peer(peer);
        }

        let mut state = DriverState {
            streams: HashMap::new(),
            runtime_tx: tx,
            max_concurrent_message_writes: config.max_concurrent_message_writes,
            pending_fsm_events: VecDeque::new(),
        };

        let mut in_flight = Vec::new();
        let mut pairing_decision = None;
        let mut timer = platform.timer();
        let recv_future = rx.recv();
        let mut recv_future = pin!(recv_future);

        loop {
            state.fill_write_slots(&mut fsm, &platform, &mut in_flight);
            state.sync_pairing_decision_state(&fsm, &mut pairing_decision);
            timer.set_deadline(fsm.next_deadline());

            match next_driver_event(
                recv_future.as_mut(),
                &mut timer,
                &mut in_flight,
                &mut pairing_decision,
            )
            .await
            {
                DriverEvent::Command(command) => {
                    state.drive_command(&mut fsm, command, &platform, &mut pairing_decision);
                }
                DriverEvent::WriteCompleted { index, success } => {
                    let write = in_flight.swap_remove(index);
                    DriverState::drive_write_completed(&mut fsm, write.session_write_id, success);
                }
                DriverEvent::PairingDecision { token, accept } => {
                    pairing_decision = None;
                    let _ = state.with_fsm_events(
                        &mut fsm,
                        &platform,
                        &mut pairing_decision,
                        |fsm, emit| {
                            if accept {
                                fsm.accept_pairing(now(), token, &platform, emit)
                            } else {
                                fsm.reject_pairing(token)
                            }
                        },
                    );
                }
                DriverEvent::TimerExpired => {
                    state.with_fsm_events(
                        &mut fsm,
                        &platform,
                        &mut pairing_decision,
                        |fsm, emit| fsm.on_timer(now(), emit),
                    );
                }
                DriverEvent::CommandsClosed => {
                    if in_flight.is_empty() && pairing_decision.is_none() {
                        break;
                    }
                }
            }
        }
    }
}

struct InFlightWrite<F> {
    session_write_id: Option<SessionWriteId>,
    future: F,
}

struct InFlightPairingDecision<'a> {
    token: PairingToken,
    future: PlatformFuture<'a, bool>,
}

enum DriverEvent {
    Command(RuntimeCommand),
    WriteCompleted { index: usize, success: bool },
    PairingDecision { token: PairingToken, accept: bool },
    TimerExpired,
    CommandsClosed,
}

#[allow(clippy::future_not_send)]
async fn next_driver_event<T, F>(
    mut recv_future: Pin<&mut async_channel::Recv<'_, RuntimeCommand>>,
    timer: &mut T,
    in_flight: &mut [InFlightWrite<F>],
    pairing_decision: &mut Option<InFlightPairingDecision<'_>>,
) -> DriverEvent
where
    T: QlTimer,
    F: Future<Output = bool> + Unpin,
{
    poll_fn(|cx| {
        for (index, write) in in_flight.iter_mut().enumerate() {
            if let Poll::Ready(success) = Pin::new(&mut write.future).poll(cx) {
                return Poll::Ready(DriverEvent::WriteCompleted { index, success });
            }
        }

        if let Some(decision) = pairing_decision.as_mut() {
            if let Poll::Ready(accept) = Pin::new(&mut decision.future).poll(cx) {
                return Poll::Ready(DriverEvent::PairingDecision {
                    token: decision.token,
                    accept,
                });
            }
        }

        if timer.poll_wait(cx) == Poll::Ready(()) {
            return Poll::Ready(DriverEvent::TimerExpired);
        }

        recv_future
            .as_mut()
            .poll(cx)
            .map(|res| res.map_or_else(|_| DriverEvent::CommandsClosed, DriverEvent::Command))
    })
    .await
}

impl DriverState {
    fn drive_command<'a, P: QlPlatform + 'a>(
        &mut self,
        fsm: &mut QlFsm,
        command: RuntimeCommand,
        platform: &'a P,
        pairing_decision: &mut Option<InFlightPairingDecision<'a>>,
    ) {
        match command {
            RuntimeCommand::BindPeer { peer } => {
                fsm.bind_peer(peer);
            }
            RuntimeCommand::Connect => {
                let _ = self.with_fsm_events(fsm, platform, pairing_decision, |fsm, emit| {
                    fsm.connect_ik(now(), platform, emit)
                });
            }
            RuntimeCommand::ArmPairing { token } => {
                fsm.arm_pairing(token);
            }
            RuntimeCommand::DisarmPairing => {
                fsm.disarm_pairing();
            }
            RuntimeCommand::StartPairing { token } => {
                let _ = self.with_fsm_events(fsm, platform, pairing_decision, |fsm, emit| {
                    fsm.connect_xx(now(), token, platform, emit)
                });
            }
            RuntimeCommand::Incoming(bytes) => {
                let _ = self.with_fsm_events(fsm, platform, pairing_decision, |fsm, emit| {
                    fsm.receive(now(), bytes, platform, emit)
                });
            }
            RuntimeCommand::OpenStream {
                request_reader,
                request_terminal,
                start,
            } => {
                let Some(runtime_tx) = self.runtime_tx.upgrade() else {
                    let _ = start.send(Err(ql_fsm::NoSessionError));
                    return;
                };

                let mut stream_ops = match fsm.open_stream() {
                    Ok(stream_ops) => stream_ops,
                    Err(error) => {
                        let _ = start.send(Err(error));
                        return;
                    }
                };
                let stream_id = stream_ops.stream_id();
                let (response_reader, response_writer) = chunk_slot::new();
                let (response_terminal_tx, response_terminal_rx) = oneshot::channel();
                self.streams.insert(
                    stream_id,
                    DriverStreamIo::new(
                        true,
                        Some(OutboundIo::new(request_reader, request_terminal)),
                        Some(InboundIo::new(response_writer, response_terminal_tx)),
                    ),
                );
                let reader = ByteReader::new(
                    stream_id,
                    CloseTarget::Return,
                    response_reader,
                    response_terminal_rx,
                    RuntimeHandle::new(runtime_tx),
                );
                if start.send(Ok((stream_id, reader))).is_err() {
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        stream.inbound_close();
                        stream.outbound_close();
                    }
                    stream_ops.close(CloseTarget::Both, StreamCloseCode(0));
                    return;
                }
                drop(stream_ops);
                self.poll_stream(fsm, stream_id);
            }
            RuntimeCommand::PollInbound { stream_id } => {
                self.handle_inbound_readable(fsm, stream_id);
            }
            RuntimeCommand::PollStream { stream_id } => {
                self.poll_stream(fsm, stream_id);
            }
            RuntimeCommand::CloseStream {
                stream_id,
                target,
                code,
            } => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    if target == CloseTarget::Both || target == stream.inbound_target() {
                        stream.inbound_close();
                    }
                    if target == CloseTarget::Both || target == stream.outbound_target() {
                        stream.outbound_close();
                    }
                }
                if let Ok(mut stream) = fsm.stream(stream_id) {
                    stream.close(target, code);
                }
                self.try_reap_stream(stream_id);
            }
        }
    }

    fn drive_write_completed(
        fsm: &mut QlFsm,
        session_write_id: Option<SessionWriteId>,
        success: bool,
    ) {
        if let Some(write_id) = session_write_id {
            if success {
                fsm.confirm_session_write(now(), write_id);
            } else {
                fsm.reject_session_write(write_id);
            }
        }
    }

    fn with_fsm_events<'a, P: QlPlatform + 'a, T>(
        &mut self,
        fsm: &mut QlFsm,
        platform: &'a P,
        pairing_decision: &mut Option<InFlightPairingDecision<'a>>,
        run: impl FnOnce(&mut QlFsm, &mut dyn FnMut(QlFsmEvent)) -> T,
    ) -> T {
        let output = {
            let pending = &mut self.pending_fsm_events;
            let mut emit = |event| pending.push_back(event);
            run(fsm, &mut emit)
        };
        self.process_pending_fsm_events(fsm, platform, pairing_decision);
        output
    }

    fn process_pending_fsm_events<'a, P: QlPlatform + 'a>(
        &mut self,
        fsm: &mut QlFsm,
        platform: &'a P,
        pairing_decision: &mut Option<InFlightPairingDecision<'a>>,
    ) {
        while let Some(event) = self.pending_fsm_events.pop_front() {
            self.process_fsm_event(fsm, platform, pairing_decision, event);
        }
    }

    fn process_fsm_event<'a, P: QlPlatform + 'a>(
        &mut self,
        fsm: &mut QlFsm,
        platform: &'a P,
        pairing_decision: &mut Option<InFlightPairingDecision<'a>>,
        event: QlFsmEvent,
    ) {
        match event {
            QlFsmEvent::NewPeer => {
                if let Some(peer) = fsm.peer().cloned() {
                    platform.persist_peer(peer);
                }
            }
            QlFsmEvent::PairingPending => {
                if let Some((token, peer)) = fsm.pending_xx_pairing() {
                    let peer = peer.clone();
                    *pairing_decision = Some(InFlightPairingDecision {
                        token,
                        future: Box::pin(async move {
                            platform.handle_pairing_request(token, peer).await
                        }),
                    });
                }
            }
            QlFsmEvent::PeerStatusChanged(status) => {
                if let Some(peer) = fsm.peer().map(|peer| peer.xid) {
                    platform.handle_peer_status(peer, status);
                }
            }
            QlFsmEvent::Opened(stream_id) => {
                self.handle_opened_stream(fsm, platform, stream_id);
            }
            QlFsmEvent::Readable(stream_id) => {
                self.handle_inbound_readable(fsm, stream_id);
            }
            QlFsmEvent::Writable(stream_id) => {
                self.poll_stream(fsm, stream_id);
            }
            QlFsmEvent::Finished(stream_id) => {
                self.handle_inbound_finished(fsm, stream_id);
            }
            QlFsmEvent::Closed(frame) => {
                self.handle_closed_stream(&frame);
            }
            QlFsmEvent::WritableClosed(frame) => {
                self.handle_writable_closed(&frame);
            }
            QlFsmEvent::SessionClosed(_) => self.fail_all_streams(),
        }
    }

    fn handle_opened_stream<P: QlPlatform>(
        &mut self,
        fsm: &mut QlFsm,
        platform: &P,
        stream_id: StreamId,
    ) {
        let Some(runtime_tx) = self.runtime_tx.upgrade() else {
            if let Ok(mut stream) = fsm.stream(stream_id) {
                stream.close(CloseTarget::Both, StreamCloseCode(0));
            }
            return;
        };

        let (request_reader, request_writer) = chunk_slot::new();
        let (request_terminal_tx, request_terminal_rx) = oneshot::channel();
        let (response_reader, response_writer) = chunk_slot::new();
        let (response_terminal_tx, response_terminal_rx) = oneshot::channel();

        self.streams.insert(
            stream_id,
            DriverStreamIo::new(
                false,
                Some(OutboundIo::new(response_reader, response_terminal_tx)),
                Some(InboundIo::new(request_writer, request_terminal_tx)),
            ),
        );

        platform.handle_inbound(QlStream {
            stream_id,
            reader: ByteReader::new(
                stream_id,
                CloseTarget::Origin,
                request_reader,
                request_terminal_rx,
                RuntimeHandle::new(runtime_tx.clone()),
            ),
            writer: ByteWriter::new(
                stream_id,
                CloseTarget::Return,
                response_writer,
                response_terminal_rx,
                RuntimeHandle::new(runtime_tx),
            ),
        });
    }

    fn handle_inbound_readable(&mut self, fsm: &mut QlFsm, stream_id: StreamId) {
        let Ok(mut stream_ops) = fsm.stream(stream_id) else {
            return;
        };
        if stream_ops.readable_bytes() == 0 {
            return;
        }
        let mut accepted = 0usize;
        let mut peer_closed = false;
        let target;
        {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return;
            };
            target = stream.inbound_target();
            for chunk in stream_ops.read() {
                if chunk.is_empty() {
                    continue;
                }
                match stream.inbound_try_write(chunk) {
                    InboundWriteResult::Accepted(n) => {
                        accepted += n;
                    }
                    InboundWriteResult::Full => {
                        break;
                    }
                    InboundWriteResult::Closed => {
                        peer_closed = true;
                        break;
                    }
                }
            }
        }

        if accepted > 0 {
            stream_ops.commit_read(accepted).unwrap();
        }
        if peer_closed {
            stream_ops.close(target, StreamCloseCode(0));
            self.try_reap_stream(stream_id);
        }

        drop(stream_ops);
        self.finish_inbound_if_ready(fsm, stream_id);
    }

    fn handle_inbound_finished(&mut self, fsm: &mut QlFsm, stream_id: StreamId) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        stream.inbound_queue_finish();
        self.finish_inbound_if_ready(fsm, stream_id);
    }

    fn finish_inbound_if_ready(&mut self, fsm: &mut QlFsm, stream_id: StreamId) {
        if let Ok(stream_ops) = fsm.stream(stream_id) {
            if stream_ops.readable_bytes() != 0 {
                return;
            }
        }

        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        if !stream.inbound_finish_pending() {
            return;
        }

        stream.inbound_finish();
        self.try_reap_stream(stream_id);
    }

    fn handle_closed_stream(&mut self, frame: &ql_wire::StreamClose) {
        let Some(stream) = self.streams.get_mut(&frame.stream_id) else {
            return;
        };

        if frame.target == CloseTarget::Both || frame.target == stream.inbound_target() {
            stream.inbound_fail(QlStreamError::StreamClosed { code: frame.code });
        }
        if frame.target == CloseTarget::Both || frame.target == stream.outbound_target() {
            stream.outbound_fail(QlStreamError::StreamClosed { code: frame.code });
        }
        self.try_reap_stream(frame.stream_id);
    }

    fn handle_writable_closed(&mut self, frame: &ql_wire::StreamClose) {
        let Some(stream) = self.streams.get_mut(&frame.stream_id) else {
            return;
        };
        stream.outbound_fail(QlStreamError::StreamClosed { code: frame.code });
        self.try_reap_stream(frame.stream_id);
    }

    fn fail_all_streams(&mut self) {
        for stream in self.streams.values_mut() {
            stream.fail_all();
        }
        self.streams.clear();
    }

    fn sync_pairing_decision_state(
        &self,
        fsm: &QlFsm,
        pairing_decision: &mut Option<InFlightPairingDecision<'_>>,
    ) {
        if let Some(decision) = pairing_decision.as_ref() {
            let is_current = fsm
                .pending_xx_pairing()
                .is_some_and(|(token, _)| token == decision.token);
            if !is_current {
                *pairing_decision = None;
            }
        }
    }

    fn fill_write_slots<'a, P: QlPlatform + 'a>(
        &self,
        fsm: &mut QlFsm,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<P::WriteMessageFut<'a>>>,
    ) {
        while in_flight.len() < self.max_concurrent_message_writes {
            let Some(write) = fsm.take_next_write(now(), platform) else {
                break;
            };
            in_flight.push(InFlightWrite {
                session_write_id: write.session_write_id,
                future: platform.write_message(write.record),
            });
        }
    }

    fn poll_stream(&mut self, fsm: &mut QlFsm, stream_id: StreamId) {
        let Entry::Occupied(mut entry) = self.streams.entry(stream_id) else {
            return;
        };
        let stream = entry.get_mut();
        let Some(reader) = stream.outbound_reader_mut() else {
            return;
        };

        if reader.is_finished() {
            if let Ok(mut stream_ops) = fsm.stream(stream_id) {
                if let Some(writer) = stream_ops.writer() {
                    writer.finish();
                }
            }
            stream.outbound_close();
            if stream.is_closed() {
                entry.remove();
            }
            return;
        }

        let Ok(mut stream_ops) = fsm.stream(stream_id) else {
            return;
        };
        let Some(mut writer) = stream_ops.writer() else {
            return;
        };

        let capacity = writer.capacity();
        if capacity > 0 {
            if let Ok(Some(mut bytes)) = reader.try_recv(capacity) {
                let _ = writer.write(&mut bytes);
            }
        }

        if reader.is_finished() {
            writer.finish();
            stream.outbound_close();
            if stream.is_closed() {
                entry.remove();
            }
        }
    }

    fn try_reap_stream(&mut self, stream_id: StreamId) {
        let should_reap = self
            .streams
            .get(&stream_id)
            .is_some_and(DriverStreamIo::is_closed);
        if should_reap {
            self.streams.remove(&stream_id);
        }
    }
}

fn now() -> FsmTime {
    FsmTime {
        instant: Instant::now(),
        unix_secs: unix_now_secs(),
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}
