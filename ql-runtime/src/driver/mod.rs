mod state;
#[cfg(test)]
mod test;

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    task::Poll,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures_lite::future::poll_fn;
use ql_fsm::{FsmTime, QlFsm, QlFsmEvent, SessionWriteId};
use ql_wire::{CloseTarget, StreamCloseCode, StreamId};

use self::state::{DriverState, DriverStreamIo, InboundWriteResult};
use crate::{
    chunk_slot,
    command::RuntimeCommand,
    handle::{ByteReader, ByteWriter, QlStream},
    platform::{PlatformFuture, QlPlatform},
    QlError, Runtime,
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
        let mut peer_xid = None;
        if let Some(peer) = platform.load_peer().await {
            peer_xid = Some(peer.xid);
            fsm.bind_peer(peer);
        }

        let mut state = DriverState {
            streams: HashMap::new(),
            runtime_tx: tx,
            max_concurrent_message_writes: config.max_concurrent_message_writes,
            peer_xid,
            pending_fsm_events: VecDeque::new(),
        };
        let mut in_flight = Vec::new();

        loop {
            state.finish_step(&mut fsm, &platform, &mut in_flight);

            if rx.is_closed() && in_flight.is_empty() {
                break;
            }

            match next_driver_event(&rx, &platform, fsm.next_deadline(), &mut in_flight).await {
                DriverEvent::Command(command) => {
                    state.drive_command(&mut fsm, command, &platform, &mut in_flight);
                }
                DriverEvent::WriteCompleted { index, success } => {
                    let write = in_flight.swap_remove(index);
                    state.drive_write_completed(
                        &mut fsm,
                        write.session_write_id,
                        success,
                        &platform,
                        &mut in_flight,
                    );
                }
                DriverEvent::TimerExpired => {
                    state.with_fsm_events(&mut fsm, &platform, |fsm, emit| {
                        fsm.on_timer(now(), emit);
                    });
                    state.finish_step(&mut fsm, &platform, &mut in_flight);
                }
                DriverEvent::CommandsClosed => {}
            }
        }
    }
}

struct InFlightWrite<'a> {
    session_write_id: Option<SessionWriteId>,
    future: PlatformFuture<'a, Result<(), QlError>>,
}

enum DriverEvent {
    Command(RuntimeCommand),
    WriteCompleted { index: usize, success: bool },
    TimerExpired,
    CommandsClosed,
}

#[allow(clippy::future_not_send)]
async fn next_driver_event<P: QlPlatform>(
    rx: &async_channel::Receiver<RuntimeCommand>,
    platform: &P,
    next_timer: Option<Instant>,
    in_flight: &mut [InFlightWrite<'_>],
) -> DriverEvent {
    let mut recv_future = (!rx.is_closed()).then(|| Box::pin(rx.recv()));
    let mut sleep_future = next_timer.map(|deadline| {
        let timeout = deadline.saturating_duration_since(Instant::now());
        platform.sleep(timeout)
    });

    poll_fn(|cx| {
        for (index, write) in in_flight.iter_mut().enumerate() {
            if let Poll::Ready(result) = write.future.as_mut().poll(cx) {
                return Poll::Ready(DriverEvent::WriteCompleted {
                    index,
                    success: result.is_ok(),
                });
            }
        }

        if let Some(future) = sleep_future.as_mut() {
            if future.as_mut().poll(cx) == Poll::Ready(()) {
                return Poll::Ready(DriverEvent::TimerExpired);
            }
        }

        if let Some(future) = recv_future.as_mut() {
            if let Poll::Ready(res) = future.as_mut().poll(cx) {
                return Poll::Ready(
                    res.map_or_else(|_| DriverEvent::CommandsClosed, DriverEvent::Command),
                );
            }
        }

        Poll::Pending
    })
    .await
}

impl DriverState {
    fn drive_command<'a, P: QlPlatform>(
        &mut self,
        fsm: &mut QlFsm,
        command: RuntimeCommand,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) {
        match command {
            RuntimeCommand::BindPeer { peer } => {
                self.peer_xid = Some(peer.xid);
                fsm.bind_peer(peer);
                self.finish_step(fsm, platform, in_flight);
            }
            RuntimeCommand::Connect => {
                let _ = self.with_fsm_events(fsm, platform, |fsm, emit| {
                    fsm.connect_ik(now(), platform, emit)
                });
                self.finish_step(fsm, platform, in_flight);
            }
            RuntimeCommand::Incoming(bytes) => {
                let _ = self.with_fsm_events(fsm, platform, |fsm, emit| {
                    fsm.receive(now(), bytes, platform, emit)
                });
                self.finish_step(fsm, platform, in_flight);
            }
            RuntimeCommand::OpenStream {
                request_reader,
                start,
            } => {
                let Some(runtime_tx) = self.runtime_tx.upgrade() else {
                    let _ = start.send(Err(QlError::Cancelled));
                    return;
                };

                match fsm.open_stream().map_err(QlError::from) {
                    Ok(stream_id) => {
                        let (response_reader, response_writer) = chunk_slot::new();
                        let (response_terminal_tx, response_terminal_rx) = oneshot::channel();
                        self.streams.insert(
                            stream_id,
                            DriverStreamIo::new_initiator(
                                request_reader,
                                response_writer,
                                response_terminal_tx,
                            ),
                        );
                        let reader = ByteReader::new(
                            stream_id,
                            CloseTarget::Return,
                            response_reader,
                            response_terminal_rx,
                            runtime_tx,
                        );
                        if start.send(Ok((stream_id, reader))).is_err() {
                            if let Some(stream) = self.streams.get_mut(&stream_id) {
                                stream.inbound_mut().close();
                                stream.outbound_mut().close();
                            }
                            let _ =
                                fsm.close_stream(stream_id, CloseTarget::Both, StreamCloseCode(0));
                            return;
                        }
                        self.poll_stream(fsm, stream_id);
                        self.finish_step(fsm, platform, in_flight);
                    }
                    Err(error) => {
                        let _ = start.send(Err(error));
                    }
                }
            }
            RuntimeCommand::PollInbound { stream_id } => {
                self.handle_inbound_readable(fsm, stream_id);
                self.finish_step(fsm, platform, in_flight);
            }
            RuntimeCommand::PollStream { stream_id } => {
                self.poll_stream(fsm, stream_id);
                self.finish_step(fsm, platform, in_flight);
            }
            RuntimeCommand::CloseStream {
                stream_id,
                target,
                code,
            } => {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    if target == CloseTarget::Both || target == stream.inbound_target() {
                        stream.inbound_mut().close();
                    }
                    if target == CloseTarget::Both || target == stream.outbound_target() {
                        stream.outbound_mut().close();
                    }
                }
                let _ = fsm.close_stream(stream_id, target, code);
                self.try_reap_stream(stream_id);
                self.finish_step(fsm, platform, in_flight);
            }
        }
    }

    fn drive_write_completed<'a, P: QlPlatform>(
        &self,
        fsm: &mut QlFsm,
        session_write_id: Option<SessionWriteId>,
        success: bool,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) {
        if let Some(write_id) = session_write_id {
            if success {
                fsm.confirm_session_write(now(), write_id);
            } else {
                fsm.reject_session_write(write_id);
            }
        }
        self.finish_step(fsm, platform, in_flight);
    }

    fn finish_step<'a, P: QlPlatform>(
        &self,
        fsm: &mut QlFsm,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) {
        while self.fill_write_slots(fsm, platform, in_flight) {}
    }

    fn with_fsm_events<P: QlPlatform, T>(
        &mut self,
        fsm: &mut QlFsm,
        platform: &P,
        run: impl FnOnce(&mut QlFsm, &mut dyn FnMut(QlFsmEvent)) -> T,
    ) -> T {
        let output = {
            let pending = &mut self.pending_fsm_events;
            let mut emit = |event| pending.push_back(event);
            run(fsm, &mut emit)
        };
        self.process_pending_fsm_events(fsm, platform);
        output
    }

    fn process_pending_fsm_events<P: QlPlatform>(&mut self, fsm: &mut QlFsm, platform: &P) {
        while let Some(event) = self.pending_fsm_events.pop_front() {
            self.process_fsm_event(fsm, platform, event);
        }
    }

    fn process_fsm_event<P: QlPlatform>(
        &mut self,
        fsm: &mut QlFsm,
        platform: &P,
        event: QlFsmEvent,
    ) {
        match event {
            QlFsmEvent::NewPeer => {
                if let Some(peer) = fsm.peer().cloned() {
                    self.peer_xid = Some(peer.xid);
                    platform.persist_peer(peer);
                }
            }
            QlFsmEvent::PeerStatusChanged(status) => {
                if self.peer_xid.is_none() {
                    self.peer_xid = fsm.peer().map(|peer| peer.xid);
                }
                if let Some(peer) = self.peer_xid {
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
            QlFsmEvent::WritableClosed(stream_id) => {
                self.handle_writable_closed(stream_id);
            }
            QlFsmEvent::SessionClosed(_) => self.fail_all_streams(&QlError::SessionClosed),
        }
    }

    fn handle_opened_stream<P: QlPlatform>(
        &mut self,
        fsm: &mut QlFsm,
        platform: &P,
        stream_id: StreamId,
    ) {
        let Some(runtime_tx) = self.runtime_tx.upgrade() else {
            let _ = fsm.close_stream(stream_id, CloseTarget::Both, StreamCloseCode(0));
            return;
        };

        let (request_reader, request_writer) = chunk_slot::new();
        let (request_terminal_tx, request_terminal_rx) = oneshot::channel();
        let (response_reader, response_writer) = chunk_slot::new();

        self.streams.insert(
            stream_id,
            DriverStreamIo::new_responder(request_writer, request_terminal_tx, response_reader),
        );

        platform.handle_inbound(QlStream {
            stream_id,
            reader: ByteReader::new(
                stream_id,
                CloseTarget::Origin,
                request_reader,
                request_terminal_rx,
                runtime_tx.clone(),
            ),
            writer: ByteWriter::new(stream_id, CloseTarget::Return, response_writer, runtime_tx),
        });
    }

    fn handle_inbound_readable(&mut self, fsm: &mut QlFsm, stream_id: StreamId) {
        loop {
            let Some(_) = fsm.stream_available_bytes(stream_id) else {
                return;
            };
            let mut accepted = 0usize;
            let mut blocked = false;
            let mut peer_closed = false;
            let target;
            {
                let Some(stream) = self.streams.get_mut(&stream_id) else {
                    return;
                };
                target = stream.inbound_target();
                let Some(chunks) = fsm.stream_read(stream_id) else {
                    return;
                };
                for chunk in chunks {
                    if chunk.is_empty() {
                        continue;
                    }
                    match stream.inbound_mut().try_write(chunk) {
                        InboundWriteResult::Accepted(n) => {
                            accepted += n;
                        }
                        InboundWriteResult::Full => {
                            blocked = true;
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
                fsm.stream_read_commit(stream_id, accepted).unwrap();
            }
            if peer_closed {
                let _ = fsm.close_stream(stream_id, target, StreamCloseCode(0));
                self.try_reap_stream(stream_id);
                break;
            }
            if accepted == 0 || blocked {
                break;
            }
        }

        self.finish_inbound_if_ready(fsm, stream_id);
    }

    fn handle_inbound_finished(&mut self, fsm: &QlFsm, stream_id: StreamId) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        stream.inbound_mut().queue_finish();
        self.finish_inbound_if_ready(fsm, stream_id);
    }

    fn finish_inbound_if_ready(&mut self, fsm: &QlFsm, stream_id: StreamId) {
        if fsm.stream_available_bytes(stream_id).unwrap_or(0) != 0 {
            return;
        }

        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        if !stream.inbound_mut().finish_pending() {
            return;
        }

        stream.inbound_mut().finish();
        self.try_reap_stream(stream_id);
    }

    fn handle_closed_stream(&mut self, frame: &ql_wire::StreamClose) {
        let Some(stream) = self.streams.get_mut(&frame.stream_id) else {
            return;
        };

        if frame.target == CloseTarget::Both || frame.target == stream.inbound_target() {
            stream.inbound_mut().fail(QlError::StreamClosed {
                target: frame.target,
                code: frame.code,
            });
        }
        if frame.target == CloseTarget::Both || frame.target == stream.outbound_target() {
            stream.outbound_mut().close();
        }
        self.try_reap_stream(frame.stream_id);
    }

    fn handle_writable_closed(&mut self, stream_id: StreamId) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        stream.outbound_mut().close();
        self.try_reap_stream(stream_id);
    }

    fn fail_all_streams(&mut self, error: &QlError) {
        for stream in self.streams.values_mut() {
            stream.fail_all(error);
        }
        self.streams.clear();
    }

    fn fill_write_slots<'a, P: QlPlatform>(
        &self,
        fsm: &mut QlFsm,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<'a>>,
    ) -> bool {
        let mut progressed = false;

        while in_flight.len() < self.max_concurrent_message_writes {
            let Some(write) = fsm.take_next_write(now(), platform) else {
                break;
            };
            progressed = true;
            in_flight.push(InFlightWrite {
                session_write_id: write.session_write_id,
                future: platform.write_message(write.record),
            });
        }

        progressed
    }

    fn poll_stream(&mut self, fsm: &mut QlFsm, stream_id: StreamId) {
        let should_finish = {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return;
            };
            let Some(reader) = stream.outbound_mut().open_mut() else {
                return;
            };

            if reader.is_finished() {
                true
            } else {
                let Some(capacity) = fsm.stream_write_capacity(stream_id) else {
                    return;
                };
                if capacity > 0 {
                    if let Ok(Some(mut bytes)) = reader.try_recv(capacity) {
                        let _ = fsm.write_stream(stream_id, &mut bytes);
                    }
                }
                reader.is_finished()
            }
        };

        if should_finish {
            let _ = fsm.finish_stream(stream_id);
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.outbound_mut().close();
            }
            self.try_reap_stream(stream_id);
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
