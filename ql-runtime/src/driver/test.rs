use ql_wire::{test_identity, NoopCrypto, PeerBundle, SoftwareCrypto, StreamClose, XID};

use super::*;
use crate::{
    driver::state::{InboundIo, OutboundIo},
    io,
    platform::QlInbound,
};

pub struct NoopTimer;
pub struct NoopInbound;

impl crate::platform::QlTimer for NoopTimer {
    fn set_deadline(self: Pin<&mut Self>, _deadline: Option<Instant>) {}

    fn poll_wait(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

impl QlPlatform for NoopCrypto {
    type Timer = NoopTimer;
    type WriteMessageFut<'a> = std::future::Ready<bool>;
    type Inbound = NoopInbound;

    fn write_message(&self, _message: Vec<u8>) -> Self::WriteMessageFut<'_> {
        std::future::ready(true)
    }

    fn inbound(&mut self) -> Self::Inbound {
        NoopInbound
    }

    fn timer(&self) -> Self::Timer {
        NoopTimer
    }

    fn persist_peer(&self, _peer: PeerBundle) {}

    fn handle_peer_status(&self, _peer: Option<XID>, _status: ql_fsm::PeerStatus) {}

    fn handle_inbound(&self, _event: QlStream) {}
}

impl QlInbound for NoopInbound {
    fn poll_recv(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Vec<u8>> {
        Poll::Pending
    }
}

fn new_driver_state() -> (DriverState, QlFsm) {
    let (runtime_tx, _runtime_rx) = async_channel::unbounded();
    (
        DriverState {
            streams: HashMap::new(),
            runtime_tx: runtime_tx.downgrade(),
            max_concurrent_message_writes: 1,
        },
        QlFsm::new(
            ql_fsm::QlFsmConfig::default(),
            test_identity(&SoftwareCrypto),
            Instant::now(),
        ),
    )
}

fn new_inbound_io(capacity: usize) -> InboundIo {
    let _ = capacity;
    let (runtime_tx, _runtime_rx) = async_channel::unbounded();
    let stream = io::new_stream(
        StreamId(99u32.into()),
        CloseTarget::Origin,
        CloseTarget::Return,
        RuntimeHandle::new(runtime_tx),
    );
    let (_, _, reader_io, _) = stream;
    InboundIo::new(reader_io)
}

fn new_outbound_io() -> OutboundIo {
    let (runtime_tx, _runtime_rx) = async_channel::unbounded();
    let stream = io::new_stream(
        StreamId(100u32.into()),
        CloseTarget::Return,
        CloseTarget::Origin,
        RuntimeHandle::new(runtime_tx),
    );
    let (_, _, _, writer_io) = stream;
    OutboundIo::new(writer_io)
}

#[test]
fn handle_inbound_finished_reaps_closed_initiator_stream() {
    let (mut state, _fsm) = new_driver_state();
    let stream_id = StreamId(1u32.into());

    state.streams.insert(
        stream_id,
        DriverStreamIo::new(true, None, Some(new_inbound_io(1))),
    );

    state.handle_inbound_finished(stream_id);

    assert!(!state.streams.contains_key(&stream_id));
}

#[test]
fn handle_closed_stream_reaps_when_both_halves_close() {
    let (mut state, _fsm) = new_driver_state();
    let stream_id = StreamId(1u32.into());

    state.streams.insert(
        stream_id,
        DriverStreamIo::new(false, Some(new_outbound_io()), Some(new_inbound_io(1))),
    );

    state.handle_closed_stream(&StreamClose {
        stream_id,
        target: CloseTarget::Both,
        code: StreamCloseCode::CANCELLED,
    });

    assert!(!state.streams.contains_key(&stream_id));
}

#[test]
fn poll_stream_keeps_outbound_pending_after_local_finish_when_inbound_is_closed() {
    let (mut state, mut fsm) = new_driver_state();
    let stream_id = StreamId(1u32.into());
    let (runtime_tx, _runtime_rx) = async_channel::unbounded();
    let (_, mut writer, _, writer_io) = io::new_stream(
        stream_id,
        CloseTarget::Return,
        CloseTarget::Origin,
        RuntimeHandle::new(runtime_tx),
    );
    writer.queue_finish();
    state.streams.insert(
        stream_id,
        DriverStreamIo::new(true, Some(OutboundIo::new(writer_io)), None),
    );

    state.poll_stream(&mut fsm, stream_id);

    let stream = state.streams.get(&stream_id).unwrap();
    assert!(stream.outbound_finish_pending());
    assert!(!stream.is_closed());
}

#[test]
fn local_close_command_reaps_when_other_half_is_already_closed() {
    let (mut state, mut fsm) = new_driver_state();
    let stream_id = StreamId(1u32.into());
    let (runtime_tx, _runtime_rx) = async_channel::unbounded();
    let (_, _, _, writer_io) = io::new_stream(
        stream_id,
        CloseTarget::Return,
        CloseTarget::Origin,
        RuntimeHandle::new(runtime_tx),
    );

    state.streams.insert(
        stream_id,
        DriverStreamIo::new(true, Some(OutboundIo::new(writer_io)), None),
    );

    state.drive_command(
        &mut fsm,
        Command::CloseStream {
            stream_id,
            target: CloseTarget::Origin,
            code: StreamCloseCode::CANCELLED,
        },
        &NoopCrypto,
    );

    assert!(!state.streams.contains_key(&stream_id));
}

#[test]
fn unpaired_status_fails_and_reaps_all_streams() {
    let (mut state, mut fsm) = new_driver_state();
    let peer = test_identity(&SoftwareCrypto).bundle();
    let stream_id = StreamId(1u32.into());
    let (runtime_tx, _runtime_rx) = async_channel::unbounded();
    let (_, _, reader_io, writer_io) = io::new_stream(
        stream_id,
        CloseTarget::Origin,
        CloseTarget::Return,
        RuntimeHandle::new(runtime_tx),
    );

    state.streams.insert(
        stream_id,
        DriverStreamIo::new(
            false,
            Some(OutboundIo::new(writer_io)),
            Some(InboundIo::new(reader_io)),
        ),
    );
    fsm.bind_peer(peer);
    fsm.unpair();

    state.drain_fsm_events(&mut fsm, &NoopCrypto);

    assert!(state.streams.is_empty());
}
