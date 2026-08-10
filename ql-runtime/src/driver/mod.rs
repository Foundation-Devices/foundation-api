mod state;

use std::{
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll},
    time::Instant,
};

use async_channel::Recv;
use futures_lite::future::poll_fn;
use ql_common::{ResetCode, StreamInfo};
use ql_fsm::{Event, QlFsm, StreamResetTarget, WriteId};
use ql_wire::SessionCloseCode;

use self::state::{DriverState, DriverStreamIo};
use crate::{
    command::Command,
    io, log,
    platform::{QlInbound, QlPlatform, QlTimer},
    Runtime,
};

impl<P: QlPlatform> Runtime<P> {
    #[allow(clippy::future_not_send)]
    pub async fn run(self) {
        let Self {
            identity,
            mut platform,
            config,
            rx,
            tx,
        } = self;

        let mut fsm = QlFsm::<DriverStreamIo>::new(config.fsm, identity, Instant::now());

        let mut state = DriverState {
            runtime_tx: tx,
            max_concurrent_message_writes: config.max_concurrent_message_writes,
            terminal_write: None,
        };

        let mut in_flight = Vec::new();
        let timer = platform.timer();
        let mut timer = pin!(timer);
        let inbound = platform.inbound();
        let mut inbound = pin!(inbound);
        let recv_future = rx.recv();
        let mut recv_future = pin!(recv_future);
        let mut poll_cursor = 0usize;

        loop {
            state.drain_fsm_events(&mut fsm, &platform);
            state.fill_write_slots(&mut fsm, &platform, &mut in_flight);
            timer.as_mut().set_deadline(fsm.next_deadline());

            let step = poll_fn(|cx| {
                next_step(
                    cx,
                    recv_future.as_mut(),
                    inbound.as_mut(),
                    timer.as_mut(),
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
                DriverStep::Inbound(bytes) => {
                    log::trace!("received transport frame: len={}", bytes.len());
                    if let Err(e) = fsm.receive(Instant::now(), bytes, platform.crypto()) {
                        log::info!("receive rejected frame: error={e:?}");
                        platform.handle_recv_error(e);
                    }
                }
                DriverStep::WriteCompleted { index, success } => {
                    let write = in_flight.swap_remove(index);
                    let write_id = write.write_id;
                    log::trace!(
                        "write completed: success={success} index={index} write_id={write_id:?}",
                    );
                    if let Some(write_id) = write_id {
                        fsm.complete_write(Instant::now(), write_id, success);
                    }
                }
                DriverStep::TimerExpired => {
                    log::trace!("timer expired");
                    fsm.on_timer(Instant::now(), platform.crypto());
                }
                DriverStep::Closed => {
                    log::debug!(
                        "command channel closed: in_flight_writes={}",
                        in_flight.len()
                    );
                    in_flight.clear();
                    fsm.close_session(SessionCloseCode::CANCELLED, platform.crypto());
                    state.drain_fsm_events(&mut fsm, &platform);
                    if let Some(write) = state.terminal_write.take() {
                        let _ = platform.write_message(write.record).await;
                    }
                    break;
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
    Command(Command),
    Inbound(Vec<u8>),
    WriteCompleted { index: usize, success: bool },
    TimerExpired,
    Closed,
}

const STEP_COUNT: usize = 4;

fn next_step<T, F, I>(
    cx: &mut Context<'_>,
    mut recv_future: Pin<&mut Recv<'_, Command>>,
    mut inbound: Pin<&mut I>,
    mut timer: Pin<&mut T>,
    in_flight: &mut [InFlightWrite<F>],
    start: usize,
) -> Poll<DriverStep>
where
    T: QlTimer,
    F: Future<Output = bool> + Unpin,
    I: QlInbound,
{
    for offset in 0..STEP_COUNT {
        let step = (start + offset) % STEP_COUNT;
        let poll = match step {
            0 => recv_future
                .as_mut()
                .poll(cx)
                .map(|res| res.map_or(DriverStep::Closed, DriverStep::Command)),
            1 => inbound.as_mut().poll_recv(cx).map(DriverStep::Inbound),
            2 => {
                for (index, write) in in_flight.iter_mut().enumerate() {
                    if let Poll::Ready(success) = Pin::new(&mut write.future).poll(cx) {
                        return Poll::Ready(DriverStep::WriteCompleted { index, success });
                    }
                }
                Poll::Pending
            }
            3 => timer
                .as_mut()
                .poll_wait(cx)
                .map(|()| DriverStep::TimerExpired),
            _ => unreachable!(),
        };
        if poll.is_ready() {
            return poll;
        }
    }

    Poll::Pending
}

impl DriverState {
    #[allow(clippy::too_many_lines)]
    fn drive_command<P: QlPlatform>(
        &mut self,
        fsm: &mut QlFsm<DriverStreamIo>,
        command: Command,
        platform: &P,
    ) {
        match command {
            Command::BindPeer { peer } => {
                log::info!("binding peer");
                fsm.bind_peer(peer);
            }
            Command::Connect => {
                log::info!("starting IK connect");
                if fsm.connect_ik(Instant::now(), platform.crypto()).is_err() {
                    log::warn!("IK connect ignored: no bound peer");
                }
            }
            Command::ArmPairing { token } => {
                log::info!("arming inbound pairing");
                fsm.arm_pairing(token);
            }
            Command::DisarmPairing => {
                log::info!("disarming inbound pairing");
                fsm.disarm_pairing();
            }
            Command::StartPairing { invite } => {
                log::info!(" starting XX pairing");
                fsm.connect_xx(Instant::now(), invite, platform.crypto());
            }
            Command::CloseSession { code } => {
                log::info!("closing session: code={code:?}");
                fsm.close_session(code, platform.crypto());
            }
            Command::Unpair => {
                log::info!("unpairing peer");
                fsm.unpair(platform.crypto());
            }
            Command::OpenStream { header, start } => {
                log::info!("open stream requested");

                let mut stream = match fsm.open_stream(header) {
                    Ok(stream_ops) => stream_ops,
                    Err(error) => {
                        log::warn!("open stream failed");
                        let _ = start.send(Err(error));
                        return;
                    }
                };
                let (metadata, stream_io) = stream.split_mut();
                let stream_id = stream_io.stream_id();
                log::info!("open stream allocated: stream_id={stream_id}");
                let (reader, writer, reader_io, writer_io) =
                    io::new_stream(stream_id, self.runtime_tx.clone());
                metadata.initialize(writer_io, reader_io, stream_io);
                if start.send(Ok((reader, writer))).is_err() {
                    log::warn!("open stream cancelled before delivery: stream_id={stream_id}");
                    stream.reset(StreamResetTarget::Both, ResetCode::DROPPED);
                    return;
                }
                stream.poll_writable();
            }
            Command::PollInbound { stream_id } => {
                log::trace!("poll inbound requested: stream_id={stream_id}");
                if let Ok(mut stream) = fsm.stream(stream_id) {
                    stream.poll_readable();
                }
            }
            Command::PollStream { stream_id } => {
                log::trace!("poll stream requested: stream_id={stream_id}");
                if let Ok(mut stream) = fsm.stream(stream_id) {
                    stream.poll_writable();
                }
            }
            Command::ResetStream {
                stream_id,
                target,
                code,
            } => {
                log::debug!(
                    "reset stream command: stream_id={stream_id} target={target:?} code={code:?}"
                );
                if let Ok(mut stream) = fsm.stream(stream_id) {
                    stream.reset(target, code);
                }
            }
        }
    }

    fn drain_fsm_events<P: QlPlatform>(&mut self, fsm: &mut QlFsm<DriverStreamIo>, platform: &P) {
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
                    let peer = fsm.peer().map(|peer| peer.qid);
                    log::info!("peer status changed: peer={peer:?} status={status:?}");
                    platform.handle_peer_status(peer, status);
                }
                Event::Opened(stream_id) => {
                    log::info!("inbound stream opened: stream_id={stream_id}");
                    let Some(qid) = fsm.peer().map(|peer| peer.qid) else {
                        continue;
                    };
                    let Ok(mut stream) = fsm.stream(stream_id) else {
                        continue;
                    };
                    let (metadata, stream_io) = stream.split_mut();
                    let header = Box::<[u8]>::from(stream_io.header());
                    let (reader, writer, reader_io, writer_io) =
                        io::new_stream(stream_id, self.runtime_tx.clone());
                    metadata.initialize(writer_io, reader_io, stream_io);
                    drop(stream);

                    log::info!("delivering inbound stream to platform: stream_id={stream_id}");
                    platform.handle_inbound(
                        StreamInfo {
                            qid,
                            stream_id,
                            header,
                        },
                        crate::QlStream { writer, reader },
                    );
                }
                Event::SessionClosed { close, write } => {
                    log::info!("session closed: frame={close:?}");
                    self.terminal_write = Some(*write);
                }
                Event::Unpaired { write } => {
                    log::info!("peer unpaired");
                    if let Some(write) = write {
                        self.terminal_write = Some(*write);
                    }
                }
            }
        }
    }

    fn fill_write_slots<'a, P: QlPlatform + 'a>(
        &mut self,
        fsm: &mut QlFsm<DriverStreamIo>,
        platform: &'a P,
        in_flight: &mut Vec<InFlightWrite<P::WriteMessageFut<'a>>>,
    ) {
        while in_flight.len() < self.max_concurrent_message_writes {
            let Some(write) = self
                .terminal_write
                .take()
                .or_else(|| fsm.take_next_write(Instant::now(), platform.crypto()))
            else {
                break;
            };
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
    }
}
