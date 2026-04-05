use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use ::proptest::{collection::vec, prelude::*, test_runner::TestCaseResult};
use ql_wire::{CloseTarget, StreamCloseCode, StreamId};

use super::*;
use crate::{state::LinkState, PeerStatus, QlFsmError, QlFsmEvent, SessionWriteId};

const SLOT_COUNT: usize = 4;

#[derive(Clone, Copy, Debug)]
enum Side {
    A,
    B,
}

#[derive(Clone, Debug)]
enum Action {
    ConnectIkA,
    ConnectIkB,
    ConnectKkA,
    ConnectKkB,
    AdvanceMs(u8),
    OnTimerA,
    OnTimerB,
    OnTimerBoth,
    Pump,
    TakeNextAToB,
    TakeNextBToA,
    ConfirmTakenAToB(usize),
    ConfirmTakenBToA(usize),
    RejectTakenAToB(usize),
    RejectTakenBToA(usize),
    CaptureNextAToB,
    CaptureNextBToA,
    DeliverNextAToB,
    DeliverNextBToA,
    DropNextAToB,
    DropNextBToA,
    DeliverQueuedAToB(usize),
    DeliverQueuedBToA(usize),
    DuplicateQueuedAToB(usize),
    DuplicateQueuedBToA(usize),
    DropQueuedAToB(usize),
    DropQueuedBToA(usize),
    OpenStreamA(usize),
    OpenStreamB(usize),
    WriteA { slot: usize, bytes: Vec<u8> },
    WriteB { slot: usize, bytes: Vec<u8> },
    FinishA(usize),
    FinishB(usize),
    CloseA(usize),
    CloseB(usize),
}

#[derive(Clone, Debug)]
struct TakenWrite {
    record: Vec<u8>,
    write_id: Option<SessionWriteId>,
}

#[derive(Default)]
struct SideEventState {
    opened: BTreeSet<StreamId>,
    finished: BTreeSet<StreamId>,
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
    slots_a: [Option<StreamId>; SLOT_COUNT],
    slots_b: [Option<StreamId>; SLOT_COUNT],
    taken_a_to_b: Vec<TakenWrite>,
    taken_b_to_a: Vec<TakenWrite>,
    pending_a_to_b: Vec<Vec<u8>>,
    pending_b_to_a: Vec<Vec<u8>>,
    receive_errors: Vec<(Side, QlFsmError)>,
    events_a: SideEventState,
    events_b: SideEventState,
    known_streams: BTreeSet<StreamId>,
    expected_at_a: BTreeMap<StreamId, Vec<u8>>,
    expected_at_b: BTreeMap<StreamId, Vec<u8>>,
    received_at_a: BTreeMap<StreamId, Vec<u8>>,
    received_at_b: BTreeMap<StreamId, Vec<u8>>,
    finished_by_a: BTreeSet<StreamId>,
    finished_by_b: BTreeSet<StreamId>,
    closed_by_a: BTreeSet<StreamId>,
    closed_by_b: BTreeSet<StreamId>,
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
            slots_a: [None; SLOT_COUNT],
            slots_b: [None; SLOT_COUNT],
            taken_a_to_b: Vec::new(),
            taken_b_to_a: Vec::new(),
            pending_a_to_b: Vec::new(),
            pending_b_to_a: Vec::new(),
            receive_errors: Vec::new(),
            events_a: SideEventState::default(),
            events_b: SideEventState::default(),
            known_streams: BTreeSet::new(),
            expected_at_a: BTreeMap::new(),
            expected_at_b: BTreeMap::new(),
            received_at_a: BTreeMap::new(),
            received_at_b: BTreeMap::new(),
            finished_by_a: BTreeSet::new(),
            finished_by_b: BTreeSet::new(),
            closed_by_a: BTreeSet::new(),
            closed_by_b: BTreeSet::new(),
        }
    }

    fn connected() -> Self {
        let config = QlFsmConfig {
            session_record_ack_delay: Duration::from_millis(5),
            session_record_retransmit_timeout: Duration::from_millis(15),
            session_peer_timeout: Duration::from_secs(5),
            ..QlFsmConfig::default()
        };

        Self {
            harness: Harness::connected(config),
            slots_a: [None; SLOT_COUNT],
            slots_b: [None; SLOT_COUNT],
            taken_a_to_b: Vec::new(),
            taken_b_to_a: Vec::new(),
            pending_a_to_b: Vec::new(),
            pending_b_to_a: Vec::new(),
            receive_errors: Vec::new(),
            events_a: SideEventState {
                last_peer_status: Some(PeerStatus::Connected),
                session_epoch: 1,
                ..SideEventState::default()
            },
            events_b: SideEventState {
                last_peer_status: Some(PeerStatus::Connected),
                session_epoch: 1,
                ..SideEventState::default()
            },
            known_streams: BTreeSet::new(),
            expected_at_a: BTreeMap::new(),
            expected_at_b: BTreeMap::new(),
            received_at_a: BTreeMap::new(),
            received_at_b: BTreeMap::new(),
            finished_by_a: BTreeSet::new(),
            finished_by_b: BTreeSet::new(),
            closed_by_a: BTreeSet::new(),
            closed_by_b: BTreeSet::new(),
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

    fn apply(&mut self, action: &Action) {
        match action {
            Action::ConnectIkA => {
                let _ = self.harness.connect_ik_a();
            }
            Action::ConnectIkB => {
                let _ = self.harness.connect_ik_b();
            }
            Action::ConnectKkA => {
                let _ = self.harness.connect_kk_a();
            }
            Action::ConnectKkB => {
                let _ = self.harness.connect_kk_b();
            }
            Action::AdvanceMs(ms) => {
                self.harness
                    .advance(Duration::from_millis(u64::from(*ms) + 1));
            }
            Action::OnTimerA => self.harness.on_timer_a(),
            Action::OnTimerB => self.harness.on_timer_b(),
            Action::OnTimerBoth => {
                self.harness.on_timer_a();
                self.harness.on_timer_b();
            }
            Action::Pump => self.capture_all_outbound(),
            Action::TakeNextAToB => {
                if let Some(write) = take_unconfirmed_outbound_a(&mut self.harness) {
                    self.taken_a_to_b.push(write);
                }
            }
            Action::TakeNextBToA => {
                if let Some(write) = take_unconfirmed_outbound_b(&mut self.harness) {
                    self.taken_b_to_a.push(write);
                }
            }
            Action::ConfirmTakenAToB(index) => {
                if let Some(write) = take_taken(&mut self.taken_a_to_b, *index) {
                    confirm_taken_a(&mut self.harness, &write);
                    self.pending_a_to_b.push(write.record);
                }
            }
            Action::ConfirmTakenBToA(index) => {
                if let Some(write) = take_taken(&mut self.taken_b_to_a, *index) {
                    confirm_taken_b(&mut self.harness, &write);
                    self.pending_b_to_a.push(write.record);
                }
            }
            Action::RejectTakenAToB(index) => {
                if let Some(write) = take_taken(&mut self.taken_a_to_b, *index) {
                    reject_taken_a(&mut self.harness, &write);
                }
            }
            Action::RejectTakenBToA(index) => {
                if let Some(write) = take_taken(&mut self.taken_b_to_a, *index) {
                    reject_taken_b(&mut self.harness, &write);
                }
            }
            Action::CaptureNextAToB => {
                if let Some(record) = take_confirmed_outbound_a(&mut self.harness) {
                    self.pending_a_to_b.push(record);
                }
            }
            Action::CaptureNextBToA => {
                if let Some(record) = take_confirmed_outbound_b(&mut self.harness) {
                    self.pending_b_to_a.push(record);
                }
            }
            Action::DeliverNextAToB => {
                if let Some(record) = take_confirmed_outbound_a(&mut self.harness) {
                    self.deliver_to_b(record);
                }
            }
            Action::DeliverNextBToA => {
                if let Some(record) = take_confirmed_outbound_b(&mut self.harness) {
                    self.deliver_to_a(record);
                }
            }
            Action::DropNextAToB => {
                let _ = take_confirmed_outbound_a(&mut self.harness);
            }
            Action::DropNextBToA => {
                let _ = take_confirmed_outbound_b(&mut self.harness);
            }
            Action::DeliverQueuedAToB(index) => {
                if let Some(record) = take_pending(&mut self.pending_a_to_b, *index) {
                    self.deliver_to_b(record);
                }
            }
            Action::DeliverQueuedBToA(index) => {
                if let Some(record) = take_pending(&mut self.pending_b_to_a, *index) {
                    self.deliver_to_a(record);
                }
            }
            Action::DuplicateQueuedAToB(index) => {
                if let Some(record) = peek_pending(&self.pending_a_to_b, *index) {
                    self.deliver_to_b(record);
                }
            }
            Action::DuplicateQueuedBToA(index) => {
                if let Some(record) = peek_pending(&self.pending_b_to_a, *index) {
                    self.deliver_to_a(record);
                }
            }
            Action::DropQueuedAToB(index) => {
                let _ = take_pending(&mut self.pending_a_to_b, *index);
            }
            Action::DropQueuedBToA(index) => {
                let _ = take_pending(&mut self.pending_b_to_a, *index);
            }
            Action::OpenStreamA(slot) => {
                if let Ok(stream_id) = self.harness.a.fsm.open_stream() {
                    self.slots_a[*slot] = Some(stream_id);
                    self.known_streams.insert(stream_id);
                }
            }
            Action::OpenStreamB(slot) => {
                if let Ok(stream_id) = self.harness.b.fsm.open_stream() {
                    self.slots_b[*slot] = Some(stream_id);
                    self.known_streams.insert(stream_id);
                }
            }
            Action::WriteA { slot, bytes } => {
                if let Some(stream_id) = self.slots_a[*slot] {
                    if let Ok(accepted) = self.harness.a.fsm.write_stream(stream_id, bytes) {
                        self.expected_at_b
                            .entry(stream_id)
                            .or_default()
                            .extend_from_slice(&bytes[..accepted]);
                    }
                }
            }
            Action::WriteB { slot, bytes } => {
                if let Some(stream_id) = self.slots_b[*slot] {
                    if let Ok(accepted) = self.harness.b.fsm.write_stream(stream_id, bytes) {
                        self.expected_at_a
                            .entry(stream_id)
                            .or_default()
                            .extend_from_slice(&bytes[..accepted]);
                    }
                }
            }
            Action::FinishA(slot) => {
                if let Some(stream_id) = self.slots_a[*slot] {
                    if self.harness.a.fsm.finish_stream(stream_id).is_ok() {
                        self.finished_by_a.insert(stream_id);
                    }
                }
            }
            Action::FinishB(slot) => {
                if let Some(stream_id) = self.slots_b[*slot] {
                    if self.harness.b.fsm.finish_stream(stream_id).is_ok() {
                        self.finished_by_b.insert(stream_id);
                    }
                }
            }
            Action::CloseA(slot) => {
                if let Some(stream_id) = self.slots_a[*slot] {
                    if self
                        .harness
                        .a
                        .fsm
                        .close_stream(stream_id, CloseTarget::Both, StreamCloseCode(0))
                        .is_ok()
                    {
                        self.closed_by_a.insert(stream_id);
                        self.slots_a[*slot] = None;
                    }
                }
            }
            Action::CloseB(slot) => {
                if let Some(stream_id) = self.slots_b[*slot] {
                    if self
                        .harness
                        .b
                        .fsm
                        .close_stream(stream_id, CloseTarget::Both, StreamCloseCode(0))
                        .is_ok()
                    {
                        self.closed_by_b.insert(stream_id);
                        self.slots_b[*slot] = None;
                    }
                }
            }
        }
    }

    fn observe_and_assert(&mut self) -> TestCaseResult {
        self.drain_reads_a();
        self.drain_reads_b();
        let events_a = self.harness.drain_events_a();
        let events_b = self.harness.drain_events_b();
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
            self.harness.on_timer_a();
            self.harness.on_timer_b();
            self.capture_all_outbound();
            self.flush_pending_in_order();
            self.observe_and_assert()?;
            self.reject_all_taken();
        }

        Ok(())
    }

    fn drain_reads_a(&mut self) {
        for stream_id in self.known_streams.iter().copied().collect::<Vec<_>>() {
            let appended = drain_stream(&mut self.harness.a.fsm, stream_id);
            if !appended.is_empty() {
                self.received_at_a
                    .entry(stream_id)
                    .or_default()
                    .extend_from_slice(&appended);
            }
        }
    }

    fn drain_reads_b(&mut self) {
        for stream_id in self.known_streams.iter().copied().collect::<Vec<_>>() {
            let appended = drain_stream(&mut self.harness.b.fsm, stream_id);
            if !appended.is_empty() {
                self.received_at_b
                    .entry(stream_id)
                    .or_default()
                    .extend_from_slice(&appended);
            }
        }
    }

    fn process_events(&mut self, side: Side, events: Vec<QlFsmEvent>) -> TestCaseResult {
        for event in events {
            match event {
                QlFsmEvent::NewPeer => {}
                QlFsmEvent::PeerStatusChanged(status) => {
                    self.events_mut(side).note_peer_status(status);
                }
                QlFsmEvent::Opened(stream_id) => {
                    prop_assert!(
                        self.known_streams.contains(&stream_id),
                        "side {side:?} emitted Opened for unknown stream {stream_id:?}"
                    );
                    prop_assert!(
                        self.events_mut(side).opened.insert(stream_id),
                        "side {side:?} emitted duplicate Opened for {stream_id:?}"
                    );
                }
                QlFsmEvent::Readable(stream_id) | QlFsmEvent::Writable(stream_id) => {
                    prop_assert!(
                        self.known_streams.contains(&stream_id),
                        "side {side:?} emitted readiness for unknown stream {stream_id:?}"
                    );
                }
                QlFsmEvent::Finished(stream_id) => {
                    prop_assert!(
                        self.known_streams.contains(&stream_id),
                        "side {side:?} emitted Finished for unknown stream {stream_id:?}"
                    );
                    prop_assert!(
                        self.events_mut(side).finished.insert(stream_id),
                        "side {side:?} emitted duplicate Finished for {stream_id:?}"
                    );
                    prop_assert!(
                        !self.events(side).closed.contains(&stream_id),
                        "side {side:?} emitted Finished after Closed for {stream_id:?}"
                    );
                }
                QlFsmEvent::Closed(frame) => {
                    prop_assert!(
                        self.known_streams.contains(&frame.stream_id),
                        "side {side:?} emitted Closed for unknown stream {:?}",
                        frame.stream_id
                    );
                    prop_assert!(
                        self.events_mut(side).closed.insert(frame.stream_id),
                        "side {side:?} emitted duplicate Closed for {:?}",
                        frame.stream_id
                    );
                }
                QlFsmEvent::WritableClosed(stream_id) => {
                    prop_assert!(
                        self.known_streams.contains(&stream_id),
                        "side {side:?} emitted WritableClosed for unknown stream {stream_id:?}"
                    );
                    prop_assert!(
                        self.events_mut(side).writable_closed.insert(stream_id),
                        "side {side:?} emitted duplicate WritableClosed for {stream_id:?}"
                    );
                }
                QlFsmEvent::SessionClosed(_) => {
                    let state = self.events_mut(side);
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
        for (stream_id, received) in &self.received_at_a {
            let expected = self
                .expected_at_a
                .get(stream_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            prop_assert!(
                expected.starts_with(received),
                "side A observed non-prefix bytes on {stream_id:?}: received={received:?} expected={expected:?}"
            );
        }

        for (stream_id, received) in &self.received_at_b {
            let expected = self
                .expected_at_b
                .get(stream_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            prop_assert!(
                expected.starts_with(received),
                "side B observed non-prefix bytes on {stream_id:?}: received={received:?} expected={expected:?}"
            );
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
                    QlFsmError::NoSession
                        | QlFsmError::InvalidState
                        | QlFsmError::Expired
                        | QlFsmError::InvalidPayload
                        | QlFsmError::DecryptFailed
                ),
                "unexpected receive error on side {side:?}: {error:?}"
            );
        }

        Ok(())
    }

    fn assert_terminal_semantics(&self) -> TestCaseResult {
        for stream_id in &self.events_a.finished {
            if self.inbound_aborted(Side::A, stream_id) {
                continue;
            }
            let expected = self
                .expected_at_a
                .get(stream_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let received = self
                .received_at_a
                .get(stream_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            prop_assert_eq!(
                received,
                expected,
                "side A finished {:?} without receiving all expected bytes",
                stream_id
            );
        }

        for stream_id in &self.events_b.finished {
            if self.inbound_aborted(Side::B, stream_id) {
                continue;
            }
            let expected = self
                .expected_at_b
                .get(stream_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let received = self
                .received_at_b
                .get(stream_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            prop_assert_eq!(
                received,
                expected,
                "side B finished {:?} without receiving all expected bytes",
                stream_id
            );
        }

        let a_connected = matches!(self.harness.a.fsm.state.link, LinkState::Connected(_));
        let b_connected = matches!(self.harness.b.fsm.state.link, LinkState::Connected(_));

        for stream_id in &self.finished_by_a {
            prop_assert!(
                self.events_b.finished.contains(stream_id)
                    || self.events_b.closed.contains(stream_id)
                    || !b_connected,
                "side A finished {stream_id:?} but side B saw neither Finished nor Closed"
            );
        }

        for stream_id in &self.finished_by_b {
            prop_assert!(
                self.events_a.finished.contains(stream_id)
                    || self.events_a.closed.contains(stream_id)
                    || !a_connected,
                "side B finished {stream_id:?} but side A saw neither Finished nor Closed"
            );
        }

        for stream_id in &self.closed_by_a {
            prop_assert!(
                self.events_b.closed.contains(stream_id) || !b_connected,
                "side A closed {stream_id:?} but side B saw no Closed event"
            );
        }

        for stream_id in &self.closed_by_b {
            prop_assert!(
                self.events_a.closed.contains(stream_id) || !a_connected,
                "side B closed {stream_id:?} but side A saw no Closed event"
            );
        }

        Ok(())
    }

    fn assert_no_stream_events(&self) -> TestCaseResult {
        prop_assert!(
            self.known_streams.is_empty()
                && self.events_a.opened.is_empty()
                && self.events_b.opened.is_empty()
                && self.events_a.finished.is_empty()
                && self.events_b.finished.is_empty()
                && self.events_a.closed.is_empty()
                && self.events_b.closed.is_empty()
                && self.events_a.writable_closed.is_empty()
                && self.events_b.writable_closed.is_empty(),
            "handshake-only property observed stream activity"
        );
        Ok(())
    }

    fn assert_no_taken_writes(&self) -> TestCaseResult {
        prop_assert!(
            self.taken_a_to_b.is_empty() && self.taken_b_to_a.is_empty(),
            "cleanup left taken writes queued"
        );
        Ok(())
    }

    fn assert_quiesced(&mut self) -> TestCaseResult {
        self.reject_all_taken();

        for _ in 0..8 {
            self.capture_all_outbound();
            if self.pending_a_to_b.is_empty() && self.pending_b_to_a.is_empty() {
                break;
            }
            self.flush_pending_in_order();
            self.observe_and_assert()?;
        }

        self.capture_all_outbound();
        prop_assert!(
            self.pending_a_to_b.is_empty()
                && self.pending_b_to_a.is_empty()
                && self.taken_a_to_b.is_empty()
                && self.taken_b_to_a.is_empty(),
            "cleanup did not quiesce: taken_a={} taken_b={} pending_a={} pending_b={}",
            self.taken_a_to_b.len(),
            self.taken_b_to_a.len(),
            self.pending_a_to_b.len(),
            self.pending_b_to_a.len()
        );

        Ok(())
    }

    fn capture_all_outbound(&mut self) {
        while let Some(record) = take_confirmed_outbound_a(&mut self.harness) {
            self.pending_a_to_b.push(record);
        }

        while let Some(record) = take_confirmed_outbound_b(&mut self.harness) {
            self.pending_b_to_a.push(record);
        }
    }

    fn flush_pending_in_order(&mut self) {
        while let Some(record) = pop_front_pending(&mut self.pending_a_to_b) {
            self.deliver_to_b(record);
        }

        while let Some(record) = pop_front_pending(&mut self.pending_b_to_a) {
            self.deliver_to_a(record);
        }
    }

    fn reject_all_taken(&mut self) {
        while let Some(write) = self.taken_a_to_b.pop() {
            reject_taken_a(&mut self.harness, &write);
        }

        while let Some(write) = self.taken_b_to_a.pop() {
            reject_taken_b(&mut self.harness, &write);
        }
    }

    fn deliver_to_a(&mut self, record: Vec<u8>) {
        if let Err(error) = deliver_to_a(&mut self.harness, record) {
            self.receive_errors.push((Side::A, error));
        }
    }

    fn deliver_to_b(&mut self, record: Vec<u8>) {
        if let Err(error) = deliver_to_b(&mut self.harness, record) {
            self.receive_errors.push((Side::B, error));
        }
    }

    fn events_mut(&mut self, side: Side) -> &mut SideEventState {
        match side {
            Side::A => &mut self.events_a,
            Side::B => &mut self.events_b,
        }
    }

    fn events(&self, side: Side) -> &SideEventState {
        match side {
            Side::A => &self.events_a,
            Side::B => &self.events_b,
        }
    }

    fn inbound_aborted(&self, side: Side, stream_id: &StreamId) -> bool {
        self.events(side).closed.contains(stream_id)
            || match side {
                Side::A => self.closed_by_a.contains(stream_id),
                Side::B => self.closed_by_b.contains(stream_id),
            }
    }
}

fn take_unconfirmed_outbound_a(harness: &mut Harness) -> Option<TakenWrite> {
    let time = harness.time();
    let Node { fsm, crypto, .. } = &mut harness.a;
    let write = fsm.take_next_write(time, crypto)?;
    Some(TakenWrite {
        record: write.record,
        write_id: write.session_write_id,
    })
}

fn take_unconfirmed_outbound_b(harness: &mut Harness) -> Option<TakenWrite> {
    let time = harness.time();
    let Node { fsm, crypto, .. } = &mut harness.b;
    let write = fsm.take_next_write(time, crypto)?;
    Some(TakenWrite {
        record: write.record,
        write_id: write.session_write_id,
    })
}

fn take_confirmed_outbound_a(harness: &mut Harness) -> Option<Vec<u8>> {
    let write = take_unconfirmed_outbound_a(harness)?;
    confirm_taken_a(harness, &write);
    Some(write.record)
}

fn take_confirmed_outbound_b(harness: &mut Harness) -> Option<Vec<u8>> {
    let write = take_unconfirmed_outbound_b(harness)?;
    confirm_taken_b(harness, &write);
    Some(write.record)
}

fn confirm_taken_a(harness: &mut Harness, write: &TakenWrite) {
    if let Some(write_id) = write.write_id {
        harness.a.fsm.confirm_session_write(harness.time(), write_id);
    }
}

fn confirm_taken_b(harness: &mut Harness, write: &TakenWrite) {
    if let Some(write_id) = write.write_id {
        harness.b.fsm.confirm_session_write(harness.time(), write_id);
    }
}

fn reject_taken_a(harness: &mut Harness, write: &TakenWrite) {
    if let Some(write_id) = write.write_id {
        harness.a.fsm.reject_session_write(write_id);
    }
}

fn reject_taken_b(harness: &mut Harness, write: &TakenWrite) {
    if let Some(write_id) = write.write_id {
        harness.b.fsm.reject_session_write(write_id);
    }
}

fn deliver_to_a(harness: &mut Harness, record: Vec<u8>) -> Result<(), QlFsmError> {
    let time = harness.time();
    let Node {
        fsm,
        crypto,
        events,
    } = &mut harness.a;
    fsm.receive(time, record, crypto, |event| events.push_back(event))
}

fn deliver_to_b(harness: &mut Harness, record: Vec<u8>) -> Result<(), QlFsmError> {
    let time = harness.time();
    let Node {
        fsm,
        crypto,
        events,
    } = &mut harness.b;
    fsm.receive(time, record, crypto, |event| events.push_back(event))
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

    loop {
        let Some(chunks) = fsm.stream_read(stream_id) else {
            break;
        };

        let mut read = 0usize;
        for chunk in chunks {
            out.extend_from_slice(chunk);
            read += chunk.len();
        }

        if read == 0 {
            break;
        }

        fsm.stream_read_commit(stream_id, read).unwrap();
    }

    out
}

fn handshake_action_strategy() -> impl Strategy<Value = Action> {
    let queue_index = 0usize..6;
    prop_oneof![
        Just(Action::ConnectIkA),
        Just(Action::ConnectIkB),
        Just(Action::ConnectKkA),
        Just(Action::ConnectKkB),
        (0u8..40).prop_map(Action::AdvanceMs),
        Just(Action::OnTimerA),
        Just(Action::OnTimerB),
        Just(Action::OnTimerBoth),
        Just(Action::Pump),
        Just(Action::TakeNextAToB),
        Just(Action::TakeNextBToA),
        queue_index.clone().prop_map(Action::ConfirmTakenAToB),
        queue_index.clone().prop_map(Action::ConfirmTakenBToA),
        queue_index.clone().prop_map(Action::RejectTakenAToB),
        queue_index.clone().prop_map(Action::RejectTakenBToA),
        Just(Action::CaptureNextAToB),
        Just(Action::CaptureNextBToA),
        Just(Action::DeliverNextAToB),
        Just(Action::DeliverNextBToA),
        Just(Action::DropNextAToB),
        Just(Action::DropNextBToA),
        queue_index.clone().prop_map(Action::DeliverQueuedAToB),
        queue_index.clone().prop_map(Action::DeliverQueuedBToA),
        queue_index.clone().prop_map(Action::DuplicateQueuedAToB),
        queue_index.clone().prop_map(Action::DuplicateQueuedBToA),
        queue_index.clone().prop_map(Action::DropQueuedAToB),
        queue_index.prop_map(Action::DropQueuedBToA),
    ]
}

fn connected_action_strategy() -> impl Strategy<Value = Action> {
    let bytes = vec(any::<u8>(), 0..24);
    let slot = 0usize..SLOT_COUNT;
    let queue_index = 0usize..6;
    prop_oneof![
        (0u8..30).prop_map(Action::AdvanceMs),
        Just(Action::OnTimerA),
        Just(Action::OnTimerB),
        Just(Action::OnTimerBoth),
        Just(Action::Pump),
        Just(Action::TakeNextAToB),
        Just(Action::TakeNextBToA),
        queue_index.clone().prop_map(Action::ConfirmTakenAToB),
        queue_index.clone().prop_map(Action::ConfirmTakenBToA),
        queue_index.clone().prop_map(Action::RejectTakenAToB),
        queue_index.clone().prop_map(Action::RejectTakenBToA),
        Just(Action::CaptureNextAToB),
        Just(Action::CaptureNextBToA),
        Just(Action::DeliverNextAToB),
        Just(Action::DeliverNextBToA),
        Just(Action::DropNextAToB),
        Just(Action::DropNextBToA),
        queue_index.clone().prop_map(Action::DeliverQueuedAToB),
        queue_index.clone().prop_map(Action::DeliverQueuedBToA),
        queue_index.clone().prop_map(Action::DuplicateQueuedAToB),
        queue_index.clone().prop_map(Action::DuplicateQueuedBToA),
        queue_index.clone().prop_map(Action::DropQueuedAToB),
        queue_index.clone().prop_map(Action::DropQueuedBToA),
        slot.clone().prop_map(Action::OpenStreamA),
        slot.clone().prop_map(Action::OpenStreamB),
        (slot.clone(), bytes.clone()).prop_map(|(slot, bytes)| Action::WriteA { slot, bytes }),
        (slot.clone(), bytes).prop_map(|(slot, bytes)| Action::WriteB { slot, bytes }),
        slot.clone().prop_map(Action::FinishA),
        slot.clone().prop_map(Action::FinishB),
        slot.clone().prop_map(Action::CloseA),
        slot.prop_map(Action::CloseB),
    ]
}

fn write_tracking_action_strategy() -> impl Strategy<Value = Action> {
    let bytes = vec(any::<u8>(), 0..16);
    let slot = 0usize..SLOT_COUNT;
    let queue_index = 0usize..6;
    prop_oneof![
        slot.clone().prop_map(Action::OpenStreamA),
        slot.clone().prop_map(Action::OpenStreamB),
        (slot.clone(), bytes.clone()).prop_map(|(slot, bytes)| Action::WriteA { slot, bytes }),
        (slot.clone(), bytes).prop_map(|(slot, bytes)| Action::WriteB { slot, bytes }),
        Just(Action::TakeNextAToB),
        Just(Action::TakeNextBToA),
        queue_index.clone().prop_map(Action::ConfirmTakenAToB),
        queue_index.clone().prop_map(Action::ConfirmTakenBToA),
        queue_index.clone().prop_map(Action::RejectTakenAToB),
        queue_index.clone().prop_map(Action::RejectTakenBToA),
        queue_index.clone().prop_map(Action::DeliverQueuedAToB),
        queue_index.clone().prop_map(Action::DeliverQueuedBToA),
        queue_index.clone().prop_map(Action::DuplicateQueuedAToB),
        queue_index.clone().prop_map(Action::DuplicateQueuedBToA),
        queue_index.clone().prop_map(Action::DropQueuedAToB),
        queue_index.clone().prop_map(Action::DropQueuedBToA),
        Just(Action::Pump),
        Just(Action::OnTimerA),
        Just(Action::OnTimerB),
        Just(Action::OnTimerBoth),
        (0u8..20).prop_map(Action::AdvanceMs),
    ]
}

fn terminal_action_strategy() -> impl Strategy<Value = Action> {
    let bytes = vec(any::<u8>(), 0..16);
    let slot = 0usize..SLOT_COUNT;
    let queue_index = 0usize..6;
    prop_oneof![
        slot.clone().prop_map(Action::OpenStreamA),
        slot.clone().prop_map(Action::OpenStreamB),
        (slot.clone(), bytes.clone()).prop_map(|(slot, bytes)| Action::WriteA { slot, bytes }),
        (slot.clone(), bytes).prop_map(|(slot, bytes)| Action::WriteB { slot, bytes }),
        slot.clone().prop_map(Action::FinishA),
        slot.clone().prop_map(Action::FinishB),
        slot.clone().prop_map(Action::CloseA),
        slot.clone().prop_map(Action::CloseB),
        Just(Action::TakeNextAToB),
        Just(Action::TakeNextBToA),
        queue_index.clone().prop_map(Action::ConfirmTakenAToB),
        queue_index.clone().prop_map(Action::ConfirmTakenBToA),
        queue_index.clone().prop_map(Action::RejectTakenAToB),
        queue_index.clone().prop_map(Action::RejectTakenBToA),
        queue_index.clone().prop_map(Action::DeliverQueuedAToB),
        queue_index.clone().prop_map(Action::DeliverQueuedBToA),
        queue_index.clone().prop_map(Action::DuplicateQueuedAToB),
        queue_index.clone().prop_map(Action::DuplicateQueuedBToA),
        queue_index.clone().prop_map(Action::DropQueuedAToB),
        queue_index.clone().prop_map(Action::DropQueuedBToA),
        Just(Action::Pump),
        Just(Action::OnTimerA),
        Just(Action::OnTimerB),
        Just(Action::OnTimerBoth),
        (0u8..20).prop_map(Action::AdvanceMs),
    ]
}

proptest! {
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
    fn randomized_terminal_actions_preserve_terminal_semantics(actions in vec(terminal_action_strategy(), 1..80)) {
        let mut runner = Runner::connected();
        runner.run(&actions)?;
        runner.assert_terminal_semantics()?;
    }
}
