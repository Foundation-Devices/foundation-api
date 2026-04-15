mod state;
#[cfg(test)]
mod test;

use std::{
    collections::{
        hash_map::{Entry, OccupiedEntry},
        HashMap,
    },
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_channel::Recv;
use futures_lite::future::{poll_fn, yield_now};
use ql_fsm::{Event, FsmTime, QlFsm, WriteId};
use ql_wire::{CloseTarget, StreamCloseCode, StreamId};

use self::state::{DriverState, DriverStreamIo, InboundIo, InboundWriteResult, OutboundIo};
use crate::{
    chunk_slot,
    command::RuntimeCommand,
    handle::{QlStream, StreamReader, StreamWriter},
    log,
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
        };

        let mut in_flight = Vec::new();
        let mut timer = platform.timer();
        let recv_future = rx.recv();
        let mut recv_future = pin!(recv_future);
        let mut poll_cursor = 0usize;

        loop {
            state.drain_fsm_events(&mut fsm, &platform);
            if state.fill_write_slots(&mut fsm, &platform, &mut in_flight) {
                state.drain_fsm_events(&mut fsm, &platform);
            }
            timer.set_deadline(fsm.next_deadline());

            let step = poll_fn(|cx| {
                next_step(
                    cx,
                    recv_future.as_mut(),
                    &mut timer,
                    &mut in_flight,
                    poll_cursor,
                )
            })
            .await;
            poll_cursor = (poll_cursor + 1) % STEP_COUNT;

            match step {
                DriverStep::Command(command) => {
                    log::trace!("processing command: kind={}", command.kind());
                    state.drive_command(&mut fsm, command, &platform);
                }
                DriverStep::WriteCompleted { index, success } => {
                    let write = in_flight.swap_remove(index);
                    let write_id = write.write_id;
                    log::trace!(
                        "write completed: success={success} index={index} write_id={write_id:?}",
                    );
                    DriverState::drive_write_completed(&mut fsm, write_id, success);
                    yield_now().await;
                }
                DriverStep::TimerExpired => {
                    log::trace!("timer expired");
                    fsm.on_timer(now());
                }
                DriverStep::Closed => {
                    log::debug!(
                        "command channel closed: in_flight_writes={}",
                        in_flight.len()
                    );
                    if in_flight.is_empty() {
                        break;
                    }
                }
            }
        }
        log::info!("runtime stopped");
    }
}

struct InFlightWrite<F> {
    write_id: Option<WriteId>,
    future: F,
}

enum DriverStep {
    Command(RuntimeCommand),
    WriteCompleted { index: usize, success: bool },
    TimerExpired,
    Closed,
}

const STEP_COUNT: usize = 3;

fn next_step<T, F>(
    cx: &mut Context<'_>,
    mut recv_future: Pin<&mut Recv<'_, RuntimeCommand>>,
    timer: &mut T,
    in_flight: &mut [InFlightWrite<F>],
    start: usize,
) -> Poll<DriverStep>
where
    T: QlTimer,
    F: Future<Output = bool> + Unpin,
{
    for offset in 0..STEP_COUNT {
        let step = (start + offset) % STEP_COUNT;
        let poll = match step {
            0 => recv_future
                .as_mut()
                .poll(cx)
                .map(|res| res.map_or(DriverStep::Closed, DriverStep::Command)),
            1 => {
                for (index, write) in in_flight.iter_mut().enumerate() {
                    if let Poll::Ready(success) = Pin::new(&mut write.future).poll(cx) {
                        return Poll::Ready(DriverStep::WriteCompleted { index, success });
                    }
                }
                Poll::Pending
            }
            2 => {
                if timer.poll_wait(cx) == Poll::Ready(()) {
                    Poll::Ready(DriverStep::TimerExpired)
                } else {
                    Poll::Pending
                }
            }
            _ => unreachable!(),
        };
        if poll.is_ready() {
            return poll;
        }
    }

    Poll::Pending
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
                log::info!("binding peer");
                fsm.bind_peer(peer);
            }
            RuntimeCommand::Connect => {
                log::info!("starting IK connect");
                if fsm.connect_ik(now(), platform).is_err() {
                    log::warn!("IK connect ignored: no bound peer");
                }
            }
            RuntimeCommand::ArmPairing { token } => {
                log::info!("arming inbound pairing");
                fsm.arm_pairing(token);
            }
            RuntimeCommand::DisarmPairing => {
                log::info!("disarming inbound pairing");
                fsm.disarm_pairing();
            }
            RuntimeCommand::StartPairing { token } => {
                log::info!(" starting XX pairing");
                fsm.connect_xx(now(), token, platform);
            }
            RuntimeCommand::Receive(bytes) => {
                log::trace!("received transport frame: len={}", bytes.len());
                if let Err(e) = fsm.receive(now(), bytes, platform) {
                    log::info!("receive rejected frame: error={e:?}");
                    platform.handle_recv_error(e);
                }
            }
            RuntimeCommand::OpenStream {
                route_id,
                request_reader,
                request_terminal,
                start,
            } => {
                log::info!("open stream requested: route_id={route_id}");
                let Some(runtime_tx) = self.runtime_tx.upgrade() else {
                    log::warn!("open stream aborted: runtime channel unavailable");
                    let _ = start.send(Err(ql_fsm::NoSessionError));
                    return;
                };

                let mut stream_ops = match fsm.open_stream(route_id) {
                    Ok(stream_ops) => stream_ops,
                    Err(error) => {
                        log::warn!("open stream failed: route_id={route_id}");
                        let _ = start.send(Err(error));
                        return;
                    }
                };
                let stream_id = stream_ops.stream_id();
                log::info!("open stream allocated: route_id={route_id} stream_id={stream_id}");
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
                let reader = StreamReader::new(
                    stream_id,
                    CloseTarget::Return,
                    response_reader,
                    response_terminal_rx,
                    RuntimeHandle::new(runtime_tx),
                );
                if start.send(Ok((stream_id, reader))).is_err() {
                    log::warn!("open stream cancelled before delivery: stream_id={stream_id}");
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        stream.inbound_close();
                        stream.outbound_close();
                    }
                    stream_ops.close(CloseTarget::Both, StreamCloseCode::CANCELLED);
                    drop(stream_ops);
                    return;
                }
                drop(stream_ops);
                self.poll_stream(fsm, stream_id);
            }
            RuntimeCommand::PollInbound { stream_id } => {
                log::trace!("poll inbound requested: stream_id={stream_id}");
                self.handle_inbound_readable(fsm, stream_id);
            }
            RuntimeCommand::PollStream { stream_id } => {
                log::trace!("poll stream requested: stream_id={stream_id}");
                self.poll_stream(fsm, stream_id);
            }
            RuntimeCommand::CloseStream {
                stream_id,
                target,
                code,
            } => {
                log::debug!(
                    "close stream command: stream_id={stream_id} target={target:?} code={code:?}"
                );
                if let Entry::Occupied(mut entry) = self.streams.entry(stream_id) {
                    let stream = entry.get_mut();
                    if target == CloseTarget::Both || target == stream.inbound_target() {
                        stream.inbound_close();
                    }
                    if target == CloseTarget::Both || target == stream.outbound_target() {
                        stream.outbound_close();
                    }
                    Self::try_reap_stream(entry);
                }
                if let Ok(mut stream) = fsm.stream(stream_id) {
                    stream.close(target, code);
                }
            }
        }
    }

    fn drive_write_completed(fsm: &mut QlFsm, session_write_id: Option<WriteId>, success: bool) {
        if let Some(write_id) = session_write_id {
            fsm.complete_write(now(), write_id, success);
        }
    }

    fn drain_fsm_events<P: QlPlatform>(&mut self, fsm: &mut QlFsm, platform: &P) {
        while let Some(event) = fsm.poll_event() {
            log::trace!("polled FSM event: event={event:?}");
            match event {
                Event::NewPeer => {
                    log::info!("new ql peer");
                    if let Some(peer) = fsm.peer().cloned() {
                        platform.persist_peer(peer);
                    }
                }
                Event::PeerStatusChanged(status) => {
                    log::info!("peer status changed: status={status:?}");
                    if let Some(peer) = fsm.peer().map(|peer| peer.xid) {
                        platform.handle_peer_status(peer, status);
                    }
                }
                Event::Opened {
                    stream_id,
                    route_id,
                } => {
                    log::info!("inbound stream opened: stream_id={stream_id} route_id={route_id}");
                    self.handle_opened_stream(fsm, platform, stream_id, route_id);
                }
                Event::Readable(stream_id) => {
                    log::trace!("stream readable: stream_id={stream_id}");
                    self.handle_inbound_readable(fsm, stream_id);
                }
                Event::Writable(stream_id) => {
                    log::trace!("stream writable: stream_id={stream_id}");
                    self.poll_stream(fsm, stream_id);
                }
                Event::Finished(stream_id) => {
                    log::info!("peer finished stream writes: stream_id={stream_id}");
                    self.handle_inbound_finished(fsm, stream_id);
                }
                Event::OutboundFinished(stream_id) => {
                    log::info!("outbound finish acknowledged: stream_id={stream_id}");
                    self.handle_outbound_finished(stream_id);
                }
                Event::Closed(frame) => {
                    self.handle_closed_stream(&frame);
                }
                Event::WritableClosed(frame) => {
                    self.handle_writable_closed(&frame);
                }
                Event::SessionClosed(_close) => {
                    log::info!("session closed: frame={_close:?}");
                    for (_, mut stream) in self.streams.drain() {
                        stream.fail_all();
                    }
                }
            }
        }
    }

    fn handle_opened_stream<P: QlPlatform>(
        &mut self,
        fsm: &mut QlFsm,
        platform: &P,
        stream_id: StreamId,
        route_id: ql_wire::RouteId,
    ) {
        let Some(runtime_tx) = self.runtime_tx.upgrade() else {
            log::warn!(
                "dropping inbound stream because handle channel is unavailable: stream_id={stream_id}"
            );
            if let Ok(mut stream) = fsm.stream(stream_id) {
                stream.close(CloseTarget::Both, StreamCloseCode::CANCELLED);
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

        log::info!(
            "delivering inbound stream to platform: stream_id={stream_id} route_id={route_id}"
        );
        platform.handle_inbound(QlStream {
            stream_id,
            route_id,
            reader: StreamReader::new(
                stream_id,
                CloseTarget::Origin,
                request_reader,
                request_terminal_rx,
                RuntimeHandle::new(runtime_tx.clone()),
            ),
            writer: StreamWriter::new(
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
            log::info!("inbound readable for unknown stream: stream_id={stream_id}");
            return;
        };
        let readable = stream_ops.readable_bytes();
        if readable == 0 {
            return;
        }
        log::trace!("draining inbound bytes: stream_id={stream_id} readable={readable}");
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
                        log::debug!(
                            "inbound backpressure: stream_id={stream_id} accepted={accepted}"
                        );
                        break;
                    }
                    InboundWriteResult::Closed => {
                        log::warn!(
                            "inbound consumer closed; sending CANCELLED: stream_id={stream_id} target={target:?}"
                        );
                        peer_closed = true;
                        break;
                    }
                }
            }
        }

        if accepted > 0 {
            log::trace!("committed inbound bytes: stream_id={stream_id:?} accepted={accepted}");
            stream_ops.commit_read(accepted).unwrap();
        }
        if peer_closed {
            stream_ops.close(target, StreamCloseCode::CANCELLED);
            if let Entry::Occupied(entry) = self.streams.entry(stream_id) {
                Self::try_reap_stream(entry);
            }
        }

        drop(stream_ops);
        self.finish_inbound_if_ready(fsm, stream_id);
    }

    fn handle_inbound_finished(&mut self, fsm: &mut QlFsm, stream_id: StreamId) {
        log::info!("inbound finished event: stream_id={stream_id}");
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

        let Entry::Occupied(mut entry) = self.streams.entry(stream_id) else {
            return;
        };
        let stream = entry.get_mut();
        if !stream.inbound_finish_pending() {
            return;
        }

        log::info!("delivering clean inbound finish: stream_id={stream_id}");
        stream.inbound_finish();
        Self::try_reap_stream(entry);
    }

    fn handle_closed_stream(&mut self, frame: &ql_wire::StreamClose) {
        log::info!(
            "inbound close frame: stream_id={} target={:?} code={}",
            frame.stream_id,
            frame.target,
            frame.code
        );
        let Entry::Occupied(mut entry) = self.streams.entry(frame.stream_id) else {
            return;
        };
        let stream = entry.get_mut();

        if frame.target == CloseTarget::Both || frame.target == stream.inbound_target() {
            stream.inbound_fail(QlStreamError::StreamClosed { code: frame.code });
        }
        if frame.target == CloseTarget::Both || frame.target == stream.outbound_target() {
            stream.outbound_fail(QlStreamError::StreamClosed { code: frame.code });
        }
        Self::try_reap_stream(entry);
    }

    fn handle_writable_closed(&mut self, frame: &ql_wire::StreamClose) {
        log::info!(
            "writable close frame: stream_id={} target={:?} code={}",
            frame.stream_id,
            frame.target,
            frame.code
        );
        let Entry::Occupied(mut entry) = self.streams.entry(frame.stream_id) else {
            return;
        };
        let stream = entry.get_mut();
        stream.outbound_fail(QlStreamError::StreamClosed { code: frame.code });
        Self::try_reap_stream(entry);
    }

    fn handle_outbound_finished(&mut self, stream_id: StreamId) {
        log::info!("outbound finish acknowledged: stream_id={stream_id}");
        let Entry::Occupied(mut entry) = self.streams.entry(stream_id) else {
            return;
        };
        let stream = entry.get_mut();
        if !stream.outbound_finish_pending() {
            return;
        }
        stream.outbound_finish();
        Self::try_reap_stream(entry);
    }

    fn fill_write_slots<'a, P: QlPlatform + 'a>(
        &self,
        fsm: &mut QlFsm,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<P::WriteMessageFut<'a>>>,
    ) -> bool {
        let mut filled = false;
        while in_flight.len() < self.max_concurrent_message_writes {
            let Some(write) = fsm.take_next_write(now(), platform) else {
                break;
            };
            filled = true;
            log::trace!(
                "queueing transport write: bytes={} write_id={:?}",
                write.record.len(),
                write.write_id
            );
            in_flight.push(InFlightWrite {
                write_id: write.write_id,
                future: platform.write_message(write.record),
            });
        }
        filled
    }

    fn poll_stream(&mut self, fsm: &mut QlFsm, stream_id: StreamId) {
        let Entry::Occupied(mut entry) = self.streams.entry(stream_id) else {
            return;
        };
        let stream = entry.get_mut();
        let Some(reader) = stream.outbound_reader_mut() else {
            log::trace!("poll stream skipped without outbound reader: stream_id={stream_id}");
            return;
        };

        if reader.is_finished() {
            log::info!("observed outbound reader finished before write: stream_id={stream_id}");
            if let Ok(mut stream_ops) = fsm.stream(stream_id) {
                if let Some(writer) = stream_ops.writer() {
                    writer.finish();
                }
            }
            stream.outbound_queue_finish();
            if stream.is_closed() {
                entry.remove();
            }
            return;
        }

        let Ok(mut stream_ops) = fsm.stream(stream_id) else {
            return;
        };
        let Some(mut writer) = stream_ops.writer() else {
            log::trace!("poll stream skipped without session writer: stream_id={stream_id}");
            return;
        };

        let capacity = writer.capacity();
        log::trace!("stream write capacity: stream_id={stream_id} capacity={capacity}");
        if capacity > 0 {
            if let Ok(mut bytes) = reader.try_recv(capacity) {
                if !bytes.is_empty() {
                    let _len = bytes.len();
                    log::trace!("writing stream bytes: stream_id={stream_id} len={_len}");
                    let _ = writer.write(&mut bytes);
                }
            }
        }

        if reader.is_finished() {
            log::info!("observed outbound reader finished after write: stream_id={stream_id}");
            writer.finish();
            stream.outbound_queue_finish();
            if stream.is_closed() {
                entry.remove();
            }
        }
    }

    fn try_reap_stream(entry: OccupiedEntry<'_, StreamId, DriverStreamIo>) {
        if entry.get().is_closed() {
            entry.remove();
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
