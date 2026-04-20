use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

extern crate proptest as proptest_crate;

use bytes::Bytes;
use proptest_crate::{collection::vec, prelude::*, test_runner::TestCaseResult};
use ql_wire::{CloseTarget, StreamCloseCode, StreamId};

use super::*;

fn test_route_id() -> ql_wire::RouteId {
    ql_wire::RouteId::from_u32(1)
}
use crate::{state::LinkState, Event, PeerStatus, ReceiveError, WriteId};

const SLOT_COUNT: usize = 4;

#[derive(Clone, Debug)]
enum Action {
    ConnectIk(Side),
    ConnectKk(Side),
    AdvanceMs(u8),
    OnTimer(Side),
    OnTimerBoth,
    Pump,
    TakeNext(Side),
    ConfirmTaken {
        side: Side,
        index: usize,
    },
    RejectTaken {
        side: Side,
        index: usize,
    },
    CaptureNext(Side),
    DeliverNext(Side),
    DropNext(Side),
    DeliverQueued {
        side: Side,
        index: usize,
    },
    DuplicateQueued {
        side: Side,
        index: usize,
    },
    DropQueued {
        side: Side,
        index: usize,
    },
    OpenStream {
        side: Side,
        slot: usize,
    },
    Write {
        side: Side,
        slot: usize,
        bytes: Vec<u8>,
    },
    Finish {
        side: Side,
        slot: usize,
    },
    Close {
        side: Side,
        slot: usize,
    },
}

impl Action {
    fn confirm_taken(side: Side, index: usize) -> Self {
        Self::ConfirmTaken { side, index }
    }

    fn reject_taken(side: Side, index: usize) -> Self {
        Self::RejectTaken { side, index }
    }

    fn deliver_queued(side: Side, index: usize) -> Self {
        Self::DeliverQueued { side, index }
    }

    fn duplicate_queued(side: Side, index: usize) -> Self {
        Self::DuplicateQueued { side, index }
    }

    fn drop_queued(side: Side, index: usize) -> Self {
        Self::DropQueued { side, index }
    }

    fn open_stream(side: Side, slot: usize) -> Self {
        Self::OpenStream { side, slot }
    }

    fn write(side: Side, slot: usize, bytes: Vec<u8>) -> Self {
        Self::Write { side, slot, bytes }
    }

    fn finish(side: Side, slot: usize) -> Self {
        Self::Finish { side, slot }
    }

    fn close(side: Side, slot: usize) -> Self {
        Self::Close { side, slot }
    }
}

#[derive(Clone, Debug)]
struct TakenWrite {
    record: Vec<u8>,
    write_id: Option<WriteId>,
}

#[derive(Default)]
struct SideEventState {
    opened: BTreeSet<StreamId>,
    finished: BTreeSet<StreamId>,
    outbound_finished: BTreeSet<StreamId>,
    writable_closed: BTreeSet<StreamId>,
    closed: BTreeSet<StreamId>,
    peer_statuses: Vec<PeerStatus>,
    last_peer_status: Option<PeerStatus>,
    session_epoch: usize,
    session_closed_epoch: Option<usize>,
}

impl SideEventState {
    fn note_peer_status(&mut self, status: PeerStatus) {
        if status == PeerStatus::Connected && self.last_peer_status != Some(PeerStatus::Connected) {
            self.session_epoch = self.session_epoch.saturating_add(1);
        }
        self.peer_statuses.push(status);
        self.last_peer_status = Some(status);
    }
}

struct Runner {
    harness: Harness,
    slots: [[Option<StreamId>; SLOT_COUNT]; 2],
    taken: [Vec<TakenWrite>; 2],
    pending: [Vec<Vec<u8>>; 2],
    receive_errors: Vec<(Side, ReceiveError)>,
    events: [SideEventState; 2],
    known_streams: BTreeSet<StreamId>,
    expected: [BTreeMap<StreamId, Vec<u8>>; 2],
    received: [BTreeMap<StreamId, Vec<u8>>; 2],
    finished_by: [BTreeSet<StreamId>; 2],
    closed_by: [BTreeSet<StreamId>; 2],
}

impl Runner {
    fn handshake() -> Self {
        let config = QlFsmConfig {
            handshake_timeout: Duration::from_millis(60),
            session_record_ack_delay: Duration::from_millis(5),
            session_record_retransmit_timeout: Duration::from_millis(15),
            session_peer_timeout: Duration::from_millis(80),
            ..QlFsmConfig::default()
        };

        Self {
            harness: Harness::paired_known(config),
            slots: [[None; SLOT_COUNT]; 2],
            taken: [Vec::new(), Vec::new()],
            pending: [Vec::new(), Vec::new()],
            receive_errors: Vec::new(),
            events: [SideEventState::default(), SideEventState::default()],
            known_streams: BTreeSet::new(),
            expected: [BTreeMap::new(), BTreeMap::new()],
            received: [BTreeMap::new(), BTreeMap::new()],
            finished_by: [BTreeSet::new(), BTreeSet::new()],
            closed_by: [BTreeSet::new(), BTreeSet::new()],
        }
    }

    fn connected() -> Self {
        let config = QlFsmConfig {
            session_record_ack_delay: Duration::from_millis(5),
            session_record_retransmit_timeout: Duration::from_millis(15),
            session_peer_timeout: Duration::from_secs(5),
            ..QlFsmConfig::default()
        };
        Self::connected_with_config(config)
    }

    fn connected_with_config(config: QlFsmConfig) -> Self {
        let connected_events = || SideEventState {
            last_peer_status: Some(PeerStatus::Connected),
            session_epoch: 1,
            ..SideEventState::default()
        };

        Self {
            harness: Harness::connected(config),
            slots: [[None; SLOT_COUNT]; 2],
            taken: [Vec::new(), Vec::new()],
            pending: [Vec::new(), Vec::new()],
            receive_errors: Vec::new(),
            events: [connected_events(), connected_events()],
            known_streams: BTreeSet::new(),
            expected: [BTreeMap::new(), BTreeMap::new()],
            received: [BTreeMap::new(), BTreeMap::new()],
            finished_by: [BTreeSet::new(), BTreeSet::new()],
            closed_by: [BTreeSet::new(), BTreeSet::new()],
        }
    }

    fn run(&mut self, actions: &[Action]) -> TestCaseResult {
        for action in actions {
            self.apply(action);
            self.observe_and_assert()?;
        }

        self.cleanup()?;
        self.observe_and_assert()?;
        self.assert_terminal_semantics()?;
        self.assert_quiesced()
    }

    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    fn apply(&mut self, action: &Action) {
        match action {
            Action::ConnectIk(side) => {
                let _ = self.harness.connect_ik(*side);
            }
            Action::ConnectKk(side) => {
                let _ = self.harness.connect_kk(*side);
            }
            Action::AdvanceMs(ms) => {
                self.harness
                    .advance(Duration::from_millis(u64::from(*ms) + 1));
            }
            Action::OnTimer(side) => self.harness.on_timer(*side),
            Action::OnTimerBoth => {
                self.harness.on_timer(Side::A);
                self.harness.on_timer(Side::B);
            }
            Action::Pump => self.capture_all_outbound(),
            Action::TakeNext(side) => {
                if let Some(write) = take_unconfirmed_outbound(&mut self.harness, *side) {
                    self.taken[side.idx()].push(write);
                }
            }
            Action::ConfirmTaken { side, index } => {
                if let Some(write) = take_taken(&mut self.taken[side.idx()], *index) {
                    confirm_taken(&mut self.harness, *side, &write);
                    self.pending[side.idx()].push(write.record);
                }
            }
            Action::RejectTaken { side, index } => {
                if let Some(write) = take_taken(&mut self.taken[side.idx()], *index) {
                    reject_taken(&mut self.harness, *side, &write);
                }
            }
            Action::CaptureNext(side) => {
                if let Some(record) = take_confirmed_outbound(&mut self.harness, *side) {
                    self.pending[side.idx()].push(record);
                }
            }
            Action::DeliverNext(side) => {
                if let Some(record) = take_confirmed_outbound(&mut self.harness, *side) {
                    self.deliver_to(opposite(*side), record);
                }
            }
            Action::DropNext(side) => {
                let _ = take_confirmed_outbound(&mut self.harness, *side);
            }
            Action::DeliverQueued { side, index } => {
                if let Some(record) = take_pending(&mut self.pending[side.idx()], *index) {
                    self.deliver_to(opposite(*side), record);
                }
            }
            Action::DuplicateQueued { side, index } => {
                if let Some(record) = peek_pending(&self.pending[side.idx()], *index) {
                    self.deliver_to(opposite(*side), record);
                }
            }
            Action::DropQueued { side, index } => {
                let _ = take_pending(&mut self.pending[side.idx()], *index);
            }
            Action::OpenStream { side, slot } => {
                let stream_id = self
                    .harness
                    .node_mut(*side)
                    .fsm
                    .open_stream(test_route_id())
                    .ok()
                    .map(|stream| stream.stream_id());
                if let Some(stream_id) = stream_id {
                    self.slots[side.idx()][*slot] = Some(stream_id);
                    self.known_streams.insert(stream_id);
                }
            }
            Action::Write { side, slot, bytes } => {
                if let Some(stream_id) = self.slots[side.idx()][*slot] {
                    let mut chunk = Bytes::copy_from_slice(bytes);
                    let accepted = if let Ok(mut stream) =
                        self.harness.node_mut(*side).fsm.stream(stream_id)
                    {
                        if let Some(mut writer) = stream.writer() {
                            writer.write(&mut chunk)
                        } else {
                            0
                        }
                    } else {
                        0
                    };
                    if accepted != 0 {
                        self.expected[opposite(*side).idx()]
                            .entry(stream_id)
                            .or_default()
                            .extend_from_slice(&bytes[..accepted]);
                    }
                }
            }
            Action::Finish { side, slot } => {
                if let Some(stream_id) = self.slots[side.idx()][*slot] {
                    let finished = if let Ok(mut stream) =
                        self.harness.node_mut(*side).fsm.stream(stream_id)
                    {
                        if let Some(writer) = stream.writer() {
                            writer.finish();
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if finished {
                        self.finished_by[side.idx()].insert(stream_id);
                    }
                }
            }
            Action::Close { side, slot } => {
                if let Some(stream_id) = self.slots[side.idx()][*slot] {
                    let closed = if let Ok(mut stream) =
                        self.harness.node_mut(*side).fsm.stream(stream_id)
                    {
                        stream.close(CloseTarget::Both, StreamCloseCode::CANCELLED);
                        true
                    } else {
                        false
                    };
                    if closed {
                        self.closed_by[side.idx()].insert(stream_id);
                        self.slots[side.idx()][*slot] = None;
                    }
                }
            }
        }
    }

    fn observe_and_assert(&mut self) -> TestCaseResult {
        self.drain_reads(Side::A);
        self.drain_reads(Side::B);
        let events_a = self.harness.drain_events(Side::A);
        let events_b = self.harness.drain_events(Side::B);
        self.process_events(Side::A, events_a)?;
        self.process_events(Side::B, events_b)?;
        self.assert_prefix_invariants()?;
        self.assert_legal_link_state()?;
        self.assert_receive_errors()
    }

    fn cleanup(&mut self) -> TestCaseResult {
        let tick = self
            .harness
            .a
            .fsm
            .config
            .session_record_retransmit_timeout
            .max(self.harness.a.fsm.config.session_record_ack_delay)
            + Duration::from_millis(1);

        self.reject_all_taken();

        for _ in 0..12 {
            self.capture_all_outbound();
            self.flush_pending_in_order();
            self.capture_all_outbound();
            self.flush_pending_in_order();
            self.observe_and_assert()?;
            self.harness.advance(tick);
            self.harness.on_timer(Side::A);
            self.harness.on_timer(Side::B);
            self.capture_all_outbound();
            self.flush_pending_in_order();
            self.observe_and_assert()?;
            self.reject_all_taken();
        }

        Ok(())
    }

    fn drain_reads(&mut self, side: Side) {
        for stream_id in self.known_streams.clone() {
            let appended = drain_stream(&mut self.harness.node_mut(side).fsm, stream_id);
            if !appended.is_empty() {
                self.received[side.idx()]
                    .entry(stream_id)
                    .or_default()
                    .extend_from_slice(&appended);
            }
        }
    }

    fn process_events(&mut self, side: Side, events: Vec<Event>) -> TestCaseResult {
        for event in events {
            match event {
                Event::NewPeer => {}
                Event::PeerStatusChanged(status) => {
                    if status == PeerStatus::Unpaired {
                        let state = &mut self.events[side.idx()];
                        prop_assert!(
                            state.session_epoch > 0,
                            "side {side:?} emitted Unpaired without a connected session"
                        );
                        prop_assert!(
                            state.session_closed_epoch != Some(state.session_epoch),
                            "side {side:?} emitted duplicate terminal event in session epoch {}",
                            state.session_epoch
                        );
                        state.session_closed_epoch = Some(state.session_epoch);
                    }
                    self.events[side.idx()].note_peer_status(status);
                }
                Event::Opened { stream_id, .. } => {
                    prop_assert!(
                        self.known_streams.contains(&stream_id),
                        "side {side:?} emitted Opened for unknown stream {stream_id:?}"
                    );
                    prop_assert!(
                        self.events[side.idx()].opened.insert(stream_id),
                        "side {side:?} emitted duplicate Opened for {stream_id:?}"
                    );
                }
                Event::Readable(stream_id) | Event::Writable(stream_id) => {
                    prop_assert!(
                        self.known_streams.contains(&stream_id),
                        "side {side:?} emitted readiness for unknown stream {stream_id:?}"
                    );
                }
                Event::Finished(stream_id) => {
                    prop_assert!(
                        self.known_streams.contains(&stream_id),
                        "side {side:?} emitted Finished for unknown stream {stream_id:?}"
                    );
                    prop_assert!(
                        self.events[side.idx()].finished.insert(stream_id),
                        "side {side:?} emitted duplicate Finished for {stream_id:?}"
                    );
                    prop_assert!(
                        !self.events[side.idx()].closed.contains(&stream_id),
                        "side {side:?} emitted Finished after Closed for {stream_id:?}"
                    );
                }
                Event::OutboundFinished(stream_id) => {
                    prop_assert!(
                        self.known_streams.contains(&stream_id),
                        "side {side:?} emitted OutboundFinished for unknown stream {stream_id:?}"
                    );
                    prop_assert!(
                        self.events[side.idx()].outbound_finished.insert(stream_id),
                        "side {side:?} emitted duplicate OutboundFinished for {stream_id:?}"
                    );
                }
                Event::Closed(frame) => {
                    prop_assert!(
                        self.known_streams.contains(&frame.stream_id),
                        "side {side:?} emitted Closed for unknown stream {:?}",
                        frame.stream_id
                    );
                    prop_assert!(
                        self.events[side.idx()].closed.insert(frame.stream_id),
                        "side {side:?} emitted duplicate Closed for {:?}",
                        frame.stream_id
                    );
                }
                Event::WritableClosed(frame) => {
                    let stream_id = frame.stream_id;
                    prop_assert!(
                        self.known_streams.contains(&stream_id),
                        "side {side:?} emitted WritableClosed for unknown stream {stream_id:?}"
                    );
                    prop_assert!(
                        self.events[side.idx()].writable_closed.insert(stream_id),
                        "side {side:?} emitted duplicate WritableClosed for {stream_id:?}"
                    );
                }
                Event::SessionClosed(_) => {
                    let state = &mut self.events[side.idx()];
                    prop_assert!(
                        state.session_epoch > 0,
                        "side {side:?} emitted SessionClosed without a connected session"
                    );
                    prop_assert!(
                        state.session_closed_epoch != Some(state.session_epoch),
                        "side {side:?} emitted duplicate SessionClosed in session epoch {}",
                        state.session_epoch
                    );
                    state.session_closed_epoch = Some(state.session_epoch);
                }
            }
        }

        Ok(())
    }

    fn assert_prefix_invariants(&self) -> TestCaseResult {
        for side in [Side::A, Side::B] {
            for (stream_id, received) in &self.received[side.idx()] {
                let expected = self.expected[side.idx()]
                    .get(stream_id)
                    .map_or(&[][..], Vec::as_slice);
                prop_assert!(
                    expected.starts_with(received),
                    "side {side:?} observed non-prefix bytes on {stream_id:?}: received={received:?} expected={expected:?}"
                );
            }
        }

        Ok(())
    }

    fn assert_legal_link_state(&self) -> TestCaseResult {
        let a_connected = matches!(self.harness.a.fsm.state.link, LinkState::Connected(_));
        let b_connected = matches!(self.harness.b.fsm.state.link, LinkState::Connected(_));

        prop_assert!(
            !a_connected || self.harness.a.fsm.peer().is_some(),
            "side A reached Connected without a bound peer"
        );
        prop_assert!(
            !b_connected || self.harness.b.fsm.peer().is_some(),
            "side B reached Connected without a bound peer"
        );

        Ok(())
    }

    fn assert_receive_errors(&self) -> TestCaseResult {
        for (side, error) in &self.receive_errors {
            prop_assert!(
                matches!(
                    error,
                    ReceiveError::NoSession
                        | ReceiveError::InvalidState
                        | ReceiveError::Expired
                        | ReceiveError::InvalidPayload
                        | ReceiveError::DecryptFailed
                ),
                "unexpected receive error on side {side:?}: {error:?}"
            );
        }

        Ok(())
    }

    fn assert_terminal_semantics(&self) -> TestCaseResult {
        let a_connected = matches!(self.harness.a.fsm.state.link, LinkState::Connected(_));
        let b_connected = matches!(self.harness.b.fsm.state.link, LinkState::Connected(_));
        let connected = [a_connected, b_connected];

        for side in [Side::A, Side::B] {
            for stream_id in &self.events[side.idx()].finished {
                if self.inbound_aborted(side, *stream_id) {
                    continue;
                }
                let expected = self.expected[side.idx()]
                    .get(stream_id)
                    .map_or(&[][..], Vec::as_slice);
                let received = self.received[side.idx()]
                    .get(stream_id)
                    .map_or(&[][..], Vec::as_slice);
                prop_assert_eq!(
                    received,
                    expected,
                    "side {:?} finished {:?} without receiving all expected bytes",
                    side,
                    stream_id
                );
            }

            for stream_id in &self.finished_by[side.idx()] {
                prop_assert!(
                    self.events[opposite(side).idx()].finished.contains(stream_id)
                        || self.events[opposite(side).idx()].closed.contains(stream_id)
                        || !connected[opposite(side).idx()],
                    "side {side:?} finished {stream_id:?} but side {:?} saw neither Finished nor Closed",
                    opposite(side)
                );
            }

            for stream_id in &self.closed_by[side.idx()] {
                prop_assert!(
                    self.events[opposite(side).idx()].closed.contains(stream_id)
                        || !connected[opposite(side).idx()],
                    "side {side:?} closed {stream_id:?} but side {:?} saw no Closed event",
                    opposite(side)
                );
            }
        }

        Ok(())
    }

    fn assert_expected_delivered(&self, side: Side) -> TestCaseResult {
        for (stream_id, expected) in &self.expected[side.idx()] {
            let received = self.received[side.idx()]
                .get(stream_id)
                .map_or(&[][..], Vec::as_slice);
            prop_assert_eq!(
                received,
                expected,
                "side {:?} did not receive full payload for {:?}",
                side,
                stream_id
            );
        }

        Ok(())
    }

    fn assert_no_stream_events(&self) -> TestCaseResult {
        prop_assert!(
            self.known_streams.is_empty()
                && self.events.iter().all(|events| {
                    events.opened.is_empty()
                        && events.finished.is_empty()
                        && events.outbound_finished.is_empty()
                        && events.closed.is_empty()
                        && events.writable_closed.is_empty()
                }),
            "handshake-only property observed stream activity"
        );
        Ok(())
    }

    fn assert_no_taken_writes(&self) -> TestCaseResult {
        prop_assert!(
            self.taken.iter().all(Vec::is_empty),
            "cleanup left taken writes queued"
        );
        Ok(())
    }

    fn assert_quiesced(&mut self) -> TestCaseResult {
        self.reject_all_taken();

        for _ in 0..8 {
            self.capture_all_outbound();
            if self.pending.iter().all(Vec::is_empty) {
                break;
            }
            self.flush_pending_in_order();
            self.observe_and_assert()?;
        }

        self.capture_all_outbound();
        prop_assert!(
            self.pending.iter().all(Vec::is_empty) && self.taken.iter().all(Vec::is_empty),
            "cleanup did not quiesce: taken_a={} taken_b={} pending_a={} pending_b={}",
            self.taken[Side::A.idx()].len(),
            self.taken[Side::B.idx()].len(),
            self.pending[Side::A.idx()].len(),
            self.pending[Side::B.idx()].len()
        );

        Ok(())
    }

    fn capture_all_outbound(&mut self) {
        for side in [Side::A, Side::B] {
            while let Some(record) = take_confirmed_outbound(&mut self.harness, side) {
                self.pending[side.idx()].push(record);
            }
        }
    }

    fn flush_pending_in_order(&mut self) {
        for side in [Side::A, Side::B] {
            while let Some(record) = pop_front_pending(&mut self.pending[side.idx()]) {
                self.deliver_to(opposite(side), record);
            }
        }
    }

    fn reject_all_taken(&mut self) {
        for side in [Side::A, Side::B] {
            while let Some(write) = self.taken[side.idx()].pop() {
                reject_taken(&mut self.harness, side, &write);
            }
        }
    }

    fn deliver_to(&mut self, side: Side, record: Vec<u8>) {
        if let Err(error) = deliver_to(&mut self.harness, side, record) {
            self.receive_errors.push((side, error));
        }
    }

    fn inbound_aborted(&self, side: Side, stream_id: StreamId) -> bool {
        self.events[side.idx()].closed.contains(&stream_id)
            || self.closed_by[side.idx()].contains(&stream_id)
    }
}

fn take_unconfirmed_outbound(harness: &mut Harness, side: Side) -> Option<TakenWrite> {
    let write = harness.next_write(side)?;
    Some(TakenWrite {
        record: write.record,
        write_id: write.write_id,
    })
}

fn take_confirmed_outbound(harness: &mut Harness, side: Side) -> Option<Vec<u8>> {
    let write = take_unconfirmed_outbound(harness, side)?;
    confirm_taken(harness, side, &write);
    Some(write.record)
}

fn confirm_taken(harness: &mut Harness, side: Side, write: &TakenWrite) {
    if let Some(write_id) = write.write_id {
        harness.confirm_write(side, write_id);
    }
}

fn reject_taken(harness: &mut Harness, side: Side, write: &TakenWrite) {
    if let Some(write_id) = write.write_id {
        harness.reject_write(side, write_id);
    }
}

fn deliver_to(harness: &mut Harness, side: Side, record: Vec<u8>) -> Result<(), ReceiveError> {
    let time = harness.time();
    let Node { fsm, crypto } = harness.node_mut(side);
    fsm.receive(time, record, crypto)
}

fn take_pending(pending: &mut Vec<Vec<u8>>, index: usize) -> Option<Vec<u8>> {
    if pending.is_empty() {
        return None;
    }

    Some(pending.remove(index % pending.len()))
}

fn peek_pending(pending: &[Vec<u8>], index: usize) -> Option<Vec<u8>> {
    if pending.is_empty() {
        return None;
    }

    Some(pending[index % pending.len()].clone())
}

fn pop_front_pending(pending: &mut Vec<Vec<u8>>) -> Option<Vec<u8>> {
    if pending.is_empty() {
        None
    } else {
        Some(pending.remove(0))
    }
}

fn take_taken(taken: &mut Vec<TakenWrite>, index: usize) -> Option<TakenWrite> {
    if taken.is_empty() {
        return None;
    }

    Some(taken.remove(index % taken.len()))
}

fn drain_stream(fsm: &mut QlFsm, stream_id: StreamId) -> Vec<u8> {
    let mut out = Vec::new();
    let Ok(mut stream) = fsm.stream(stream_id) else {
        return out;
    };

    loop {
        let mut read = 0usize;
        for chunk in stream.read() {
            out.extend_from_slice(&chunk);
            read += chunk.len();
        }

        if read == 0 {
            break;
        }

        stream.commit_read(read).unwrap();
    }

    out
}

fn opposite(side: Side) -> Side {
    match side {
        Side::A => Side::B,
        Side::B => Side::A,
    }
}

fn side_strategy() -> impl Strategy<Value = Side> {
    prop_oneof![Just(Side::A), Just(Side::B)]
}

fn side_action(f: fn(Side) -> Action) -> impl Strategy<Value = Action> {
    side_strategy().prop_map(f)
}

fn side_usize_action(
    values: impl Strategy<Value = usize>,
    f: fn(Side, usize) -> Action,
) -> impl Strategy<Value = Action> {
    (side_strategy(), values).prop_map(move |(side, value)| f(side, value))
}

fn side_usize_vec_action(
    values: impl Strategy<Value = usize>,
    bytes: impl Strategy<Value = Vec<u8>>,
    f: fn(Side, usize, Vec<u8>) -> Action,
) -> impl Strategy<Value = Action> {
    (side_strategy(), values, bytes).prop_map(move |(side, value, bytes)| f(side, value, bytes))
}

fn handshake_action_strategy() -> impl Strategy<Value = Action> {
    let queue_index = 0usize..6;
    prop_oneof![
        side_action(Action::ConnectIk),
        side_action(Action::ConnectKk),
        (0u8..40).prop_map(Action::AdvanceMs),
        side_action(Action::OnTimer),
        Just(Action::OnTimerBoth),
        Just(Action::Pump),
        side_action(Action::TakeNext),
        side_usize_action(queue_index.clone(), Action::confirm_taken),
        side_usize_action(queue_index.clone(), Action::reject_taken),
        side_action(Action::CaptureNext),
        side_action(Action::DeliverNext),
        side_action(Action::DropNext),
        side_usize_action(queue_index.clone(), Action::deliver_queued),
        side_usize_action(queue_index.clone(), Action::duplicate_queued),
        side_usize_action(queue_index, Action::drop_queued),
    ]
}

fn connected_action_strategy() -> impl Strategy<Value = Action> {
    let bytes = vec(any::<u8>(), 0..24);
    let slot = 0usize..SLOT_COUNT;
    let queue_index = 0usize..6;
    prop_oneof![
        (0u8..30).prop_map(Action::AdvanceMs),
        side_action(Action::OnTimer),
        Just(Action::OnTimerBoth),
        Just(Action::Pump),
        side_action(Action::TakeNext),
        side_usize_action(queue_index.clone(), Action::confirm_taken),
        side_usize_action(queue_index.clone(), Action::reject_taken),
        side_action(Action::CaptureNext),
        side_action(Action::DeliverNext),
        side_action(Action::DropNext),
        side_usize_action(queue_index.clone(), Action::deliver_queued),
        side_usize_action(queue_index.clone(), Action::duplicate_queued),
        side_usize_action(queue_index.clone(), Action::drop_queued),
        side_usize_action(slot.clone(), Action::open_stream),
        side_usize_vec_action(slot.clone(), bytes.clone(), Action::write),
        side_usize_action(slot.clone(), Action::finish),
        side_usize_action(slot, Action::close),
    ]
}

fn write_tracking_action_strategy() -> impl Strategy<Value = Action> {
    let bytes = vec(any::<u8>(), 0..16);
    let slot = 0usize..SLOT_COUNT;
    let queue_index = 0usize..6;
    prop_oneof![
        side_usize_action(slot.clone(), Action::open_stream),
        side_usize_vec_action(slot, bytes, Action::write),
        side_action(Action::TakeNext),
        side_usize_action(queue_index.clone(), Action::confirm_taken),
        side_usize_action(queue_index.clone(), Action::reject_taken),
        side_usize_action(queue_index.clone(), Action::deliver_queued),
        side_usize_action(queue_index.clone(), Action::duplicate_queued),
        side_usize_action(queue_index, Action::drop_queued),
        Just(Action::Pump),
        side_action(Action::OnTimer),
        Just(Action::OnTimerBoth),
        (0u8..20).prop_map(Action::AdvanceMs),
    ]
}

fn packet_loss_recovery_action_strategy() -> impl Strategy<Value = Action> {
    let queue_index = 0usize..16;
    prop_oneof![
        (0u8..20).prop_map(Action::AdvanceMs),
        side_action(Action::OnTimer),
        Just(Action::OnTimerBoth),
        Just(Action::Pump),
        side_usize_action(queue_index.clone(), Action::deliver_queued),
        side_usize_action(queue_index.clone(), Action::duplicate_queued),
        side_usize_action(queue_index, Action::drop_queued),
    ]
}

fn terminal_action_strategy() -> impl Strategy<Value = Action> {
    let bytes = vec(any::<u8>(), 0..16);
    let slot = 0usize..SLOT_COUNT;
    let queue_index = 0usize..6;
    prop_oneof![
        side_usize_action(slot.clone(), Action::open_stream),
        side_usize_vec_action(slot.clone(), bytes.clone(), Action::write),
        side_usize_action(slot.clone(), Action::finish),
        side_usize_action(slot, Action::close),
        side_action(Action::TakeNext),
        side_usize_action(queue_index.clone(), Action::confirm_taken),
        side_usize_action(queue_index.clone(), Action::reject_taken),
        side_usize_action(queue_index.clone(), Action::deliver_queued),
        side_usize_action(queue_index.clone(), Action::duplicate_queued),
        side_usize_action(queue_index, Action::drop_queued),
        Just(Action::Pump),
        side_action(Action::OnTimer),
        Just(Action::OnTimerBoth),
        (0u8..20).prop_map(Action::AdvanceMs),
    ]
}

proptest_crate::proptest! {
    #![proptest_config(ProptestConfig {
        cases: 24,
        max_shrink_iters: 10_000,
        .. ProptestConfig::default()
    })]

    #[test]
    fn randomized_handshake_actions_quiesce(actions in vec(handshake_action_strategy(), 1..64)) {
        let mut runner = Runner::handshake();
        runner.run(&actions)?;
        runner.assert_no_stream_events()?;
    }

    #[test]
    fn randomized_stream_actions_preserve_integrity(actions in vec(connected_action_strategy(), 1..80)) {
        let mut runner = Runner::connected();
        runner.run(&actions)?;
    }

    #[test]
    fn randomized_write_tracking_actions_quiesce(actions in vec(write_tracking_action_strategy(), 1..80)) {
        let mut runner = Runner::connected();
        runner.run(&actions)?;
        runner.assert_no_taken_writes()?;
    }

    #[test]
    fn randomized_session_packet_loss_recovers(
        payload in vec(any::<u8>(), 512..2048),
        actions in vec(packet_loss_recovery_action_strategy(), 1..96),
    ) {
        let config = QlFsmConfig {
            session_record_ack_delay: Duration::from_millis(1),
            session_record_retransmit_timeout: Duration::from_millis(10),
            session_record_max_size: 96,
            session_pending_ack_range_limit: 512,
            ..QlFsmConfig::default()
        };
        let mut runner = Runner::connected_with_config(config);

        runner.apply(&Action::open_stream(Side::A, 0));
        runner.observe_and_assert()?;

        runner.apply(&Action::write(Side::A, 0, payload));
        runner.observe_and_assert()?;

        runner.apply(&Action::finish(Side::A, 0));
        runner.observe_and_assert()?;

        for action in &actions {
            runner.apply(action);
            runner.observe_and_assert()?;
        }

        runner.cleanup()?;
        runner.observe_and_assert()?;
        runner.assert_expected_delivered(Side::B)?;
        runner.assert_terminal_semantics()?;
        runner.assert_quiesced()?;
    }

    #[test]
    fn randomized_terminal_actions_preserve_terminal_semantics(actions in vec(terminal_action_strategy(), 1..80)) {
        let mut runner = Runner::connected();
        runner.run(&actions)?;
        runner.assert_terminal_semantics()?;
    }
}
