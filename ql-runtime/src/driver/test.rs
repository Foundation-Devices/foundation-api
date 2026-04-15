use std::task::{Context, Poll};

use ql_wire::{test_identity, NoopCrypto, PeerBundle, SoftwareCrypto, StreamClose, XID};

use super::*;
use crate::{
    chunk_slot,
    driver::state::{InboundIo, OutboundIo},
    platform::PlatformFuture,
};

pub struct NoopTimer;

impl crate::platform::QlTimer for NoopTimer {
    fn set_deadline(&mut self, _deadline: Option<std::time::Instant>) {}

    fn poll_wait(&mut self, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

impl QlPlatform for NoopCrypto {
    type Timer = NoopTimer;
    type WriteMessageFut<'a> = std::future::Ready<bool>;

    fn write_message(&self, _message: Vec<u8>) -> Self::WriteMessageFut<'_> {
        std::future::ready(true)
    }

    fn timer(&self) -> Self::Timer {
        NoopTimer
    }

    fn load_peer(&self) -> PlatformFuture<'_, Option<PeerBundle>> {
        Box::pin(async { None })
    }

    fn persist_peer(&self, _peer: PeerBundle) {}

    fn handle_peer_status(&self, _peer: XID, _status: ql_fsm::PeerStatus) {}

    fn handle_inbound(&self, _event: QlStream) {}
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
            now(),
        ),
    )
}

fn new_inbound_io(capacity: usize) -> InboundIo {
    let _ = capacity;
    let (_reader, writer) = chunk_slot::new();
    let (terminal_tx, _terminal_rx) = oneshot::channel();
    InboundIo::new(writer, terminal_tx)
}

fn new_outbound_io() -> OutboundIo {
    let (reader, _writer) = chunk_slot::new();
    let (terminal_tx, _terminal_rx) = oneshot::channel();
    OutboundIo::new(reader, terminal_tx)
}

#[test]
fn handle_inbound_finished_reaps_closed_initiator_stream() {
    let (mut state, mut fsm) = new_driver_state();
    let stream_id = StreamId(1u32.into());

    state.streams.insert(
        stream_id,
        DriverStreamIo::new(true, None, Some(new_inbound_io(1))),
    );

    state.handle_inbound_finished(&mut fsm, stream_id);

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
    let (request_reader, request_writer) = chunk_slot::new();
    let (request_terminal_tx, _request_terminal_rx) = oneshot::channel();

    drop(request_writer);
    state.streams.insert(
        stream_id,
        DriverStreamIo::new(
            true,
            Some(OutboundIo::new(request_reader, request_terminal_tx)),
            None,
        ),
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
    let (request_reader, _request_writer) = chunk_slot::new();
    let (request_terminal_tx, _request_terminal_rx) = oneshot::channel();

    state.streams.insert(
        stream_id,
        DriverStreamIo::new(
            true,
            Some(OutboundIo::new(request_reader, request_terminal_tx)),
            None,
        ),
    );

    state.drive_command(
        &mut fsm,
        RuntimeCommand::CloseStream {
            stream_id,
            target: CloseTarget::Origin,
            code: StreamCloseCode::CANCELLED,
        },
        &NoopCrypto,
    );

    assert!(!state.streams.contains_key(&stream_id));
}
