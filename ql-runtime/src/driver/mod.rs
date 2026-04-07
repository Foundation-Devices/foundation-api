mod state;
#[cfg(test)]
mod test;

use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    future::Future,
    pin::Pin,
    task::Poll,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures_lite::future::poll_fn;
use ql_fsm::{FsmTime, QlFsm, QlFsmEvent, SessionWriteId};
use ql_wire::{CloseTarget, StreamCloseCode, StreamId};

use self::state::{DriverState, DriverStreamIo, InboundIo, InboundWriteResult, OutboundIo};
use crate::{
    chunk_slot,
    command::RuntimeCommand,
    handle::{ByteReader, ByteWriter, QlStream},
    platform::{QlPlatform, QlTimer},
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
        let mut timer = platform.timer();

        loop {
            state.fill_write_slots(&mut fsm, &platform, &mut in_flight);

            if rx.is_closed() && in_flight.is_empty() {
                break;
            }

            timer.set_deadline(fsm.next_deadline());

            match next_driver_event(&rx, &mut timer, &mut in_flight).await {
                DriverEvent::Command(command) => {
                    state.drive_command(&mut fsm, command, &platform);
                }
                DriverEvent::WriteCompleted { index, success } => {
                    let write = in_flight.swap_remove(index);
                    DriverState::drive_write_completed(&mut fsm, write.session_write_id, success);
                }
                DriverEvent::TimerExpired => {
                    state.with_fsm_events(&mut fsm, &platform, |fsm, emit| {
                        fsm.on_timer(now(), emit);
                    });
                }
                DriverEvent::CommandsClosed => {}
            }
        }
    }
}

struct InFlightWrite<F> {
    session_write_id: Option<SessionWriteId>,
    future: F,
}

enum DriverEvent {
    Command(RuntimeCommand),
    WriteCompleted { index: usize, success: bool },
    TimerExpired,
    CommandsClosed,
}

#[allow(clippy::future_not_send)]
async fn next_driver_event<T, F>(
    rx: &async_channel::Receiver<RuntimeCommand>,
    timer: &mut T,
    in_flight: &mut [InFlightWrite<F>],
) -> DriverEvent
where
    T: QlTimer,
    F: Future<Output = bool> + Unpin,
{
    let mut recv_future = (!rx.is_closed()).then(|| Box::pin(rx.recv()));

    poll_fn(|cx| {
        for (index, write) in in_flight.iter_mut().enumerate() {
            if let Poll::Ready(success) = Pin::new(&mut write.future).poll(cx) {
                return Poll::Ready(DriverEvent::WriteCompleted { index, success });
            }
        }

        if timer.poll_wait(cx) == Poll::Ready(()) {
            return Poll::Ready(DriverEvent::TimerExpired);
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
    fn drive_command<P: QlPlatform>(
        &mut self,
        fsm: &mut QlFsm,
        command: RuntimeCommand,
        platform: &P,
    ) {
        match command {
            RuntimeCommand::BindPeer { peer } => {
                fsm.bind_peer(peer);
            }
            RuntimeCommand::Connect => {
                let _ = self.with_fsm_events(fsm, platform, |fsm, emit| {
                    fsm.connect_ik(now(), platform, emit)
                });
            }
            RuntimeCommand::Incoming(bytes) => {
                let _ = self.with_fsm_events(fsm, platform, |fsm, emit| {
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

                match fsm.open_stream() {
                    Ok(stream_id) => {
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
                            let _ =
                                fsm.close_stream(stream_id, CloseTarget::Both, StreamCloseCode(0));
                            return;
                        }
                        self.poll_stream(fsm, stream_id);
                    }
                    Err(error) => {
                        let _ = start.send(Err(error));
                    }
                }
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
                let _ = fsm.close_stream(stream_id, target, code);
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
                    platform.persist_peer(peer);
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
            let _ = fsm.close_stream(stream_id, CloseTarget::Both, StreamCloseCode(0));
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
                    match stream.inbound_try_write(chunk) {
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
        stream.inbound_queue_finish();
        self.finish_inbound_if_ready(fsm, stream_id);
    }

    fn finish_inbound_if_ready(&mut self, fsm: &QlFsm, stream_id: StreamId) {
        if fsm.stream_available_bytes(stream_id).unwrap_or(0) != 0 {
            return;
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
            if let Ok(writer) = fsm.write_stream(stream_id) {
                writer.finish();
            }
            stream.outbound_close();
            if stream.is_closed() {
                entry.remove();
            }
            return;
        }

        let Ok(mut writer) = fsm.write_stream(stream_id) else {
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
