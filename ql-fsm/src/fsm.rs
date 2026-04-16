use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use bytes::Bytes;
use ql_wire::{self as wire, QlCrypto, RouteId, SessionCloseCode, StreamId, WireDecode};

use crate::{
    handshake,
    session::{EventSink, SessionEvent},
    state::LinkState,
    Event, NoPeerError, NoSessionError, OutboundWrite, QlFsm, ReceiveError, StreamError, WriteId,
};

pub struct FsmEventEmitter<'a> {
    events: &'a mut VecDeque<Event>,
}

impl EventSink for FsmEventEmitter<'_> {
    fn emit(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::Opened {
                stream_id,
                route_id,
            } => {
                self.events.push_back(Event::Opened {
                    stream_id,
                    route_id,
                });
            }
            SessionEvent::Readable(stream_id) => {
                self.events.push_back(Event::Readable(stream_id));
            }
            SessionEvent::Writable(stream_id) => {
                self.events.push_back(Event::Writable(stream_id));
            }
            SessionEvent::Finished(stream_id) => {
                self.events.push_back(Event::Finished(stream_id));
            }
            SessionEvent::OutboundFinished(stream_id) => {
                self.events.push_back(Event::OutboundFinished(stream_id));
            }
            SessionEvent::Closed(frame) => {
                self.events.push_back(Event::Closed(frame));
            }
            SessionEvent::WritableClosed(frame) => {
                self.events.push_back(Event::WritableClosed(frame));
            }
            SessionEvent::SessionClosed(close) => {
                self.events.push_back(Event::SessionClosed(close));
            }
        }
    }
}

pub fn handle_bind_peer(fsm: &mut QlFsm, peer: ql_wire::PeerBundle) {
    fsm.state.handshake = None;
    fsm.state.link = LinkState::Idle;
    fsm.state.peer = Some(peer);
}

pub fn handle_disarm_pairing(fsm: &mut QlFsm) {
    fsm.state.armed_pairing_token = None;
    handshake::handle_disarm_pairing(fsm);
}

pub fn handle_connect_xx(fsm: &mut QlFsm, token: ql_wire::PairingToken, crypto: &impl QlCrypto) {
    handshake::handle_connect_xx(fsm, token, crypto);
}

pub fn handle_connect_ik(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Result<(), NoPeerError> {
    handshake::handle_connect_ik(fsm, crypto)
}

pub fn handle_connect_kk(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Result<(), NoPeerError> {
    handshake::handle_connect_kk(fsm, crypto)
}

pub fn receive(
    fsm: &mut QlFsm,
    mut bytes: Vec<u8>,
    crypto: &impl QlCrypto,
) -> Result<(), ReceiveError> {
    let mut reader = wire::Reader::new(bytes.as_mut_slice());
    let header = wire::RecordHeader::decode(&mut reader)?;

    if header.version != wire::QL_WIRE_VERSION {
        return Err(ReceiveError::InvalidPayload);
    }

    match header.record_type {
        wire::RecordType::Handshake => {
            let record = wire::QlHandshakeRecord::decode(&mut reader)?;
            handshake::handle_handshake_record(fsm, crypto, &record)
        }
        wire::RecordType::Session => {
            let QlFsm { state, events, .. } = fsm;
            let conn = state.link.connected_mut_or_err()?;
            let (decrypt_len, seq) = {
                let record = wire::QlSessionRecord::decode(&mut reader)?;
                if record.header.connection_id != conn.transport.rx_connection_id {
                    return Err(ReceiveError::InvalidPayload);
                }
                let payload = wire::decrypt_record(
                    crypto,
                    &record.header,
                    record.payload,
                    &conn.transport.rx_key,
                )?;
                (payload.len(), record.header.seq)
            };

            let len = bytes.len();
            let plaintext = Bytes::from(bytes).slice(len - decrypt_len..);
            let frames = wire::parse_session_frames(plaintext);

            let mut emit = FsmEventEmitter { events };
            conn.session
                .receive(state.now.instant, seq, frames, &mut emit);

            if conn.session.is_closed() {
                apply_session_closed(fsm);
            }
            Ok(())
        }
    }
}

pub fn on_timer(fsm: &mut QlFsm) {
    handshake::handle_timer(fsm);

    let QlFsm { state, events, .. } = fsm;
    let Some(conn) = state.link.connected_mut() else {
        return;
    };

    let mut emit = FsmEventEmitter { events };
    conn.session.on_timer(state.now.instant, &mut emit);

    if conn.session.is_closed() {
        apply_session_closed(fsm);
    }
}

pub fn next_deadline(fsm: &QlFsm) -> Option<Instant> {
    [
        handshake::next_handshake_deadline(fsm),
        fsm.state
            .link
            .connected()
            .and_then(|state| state.session.next_deadline()),
    ]
    .into_iter()
    .flatten()
    .min()
}

pub fn take_next_write(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Option<OutboundWrite> {
    if let Some(record) = fsm.state.handshake.take() {
        let record = wire::encode_record_vec(ql_wire::RecordType::Handshake, &record);
        return Some(OutboundWrite {
            record,
            write_id: None,
        });
    }

    let QlFsm { state, .. } = fsm;
    let conn = state.link.connected_mut()?;

    let (write_id, builder) = conn.session.take_next_write(state.now.instant)?;
    let record = builder.encrypt(
        crypto,
        conn.transport.tx_connection_id,
        &conn.transport.tx_key,
    );
    if conn.session.is_closed() {
        apply_session_closed(fsm);
    }
    Some(OutboundWrite {
        record,
        write_id: write_id.map(WriteId),
    })
}

pub fn complete_write(fsm: &mut QlFsm, write_id: WriteId, success: bool) {
    let QlFsm { state, .. } = fsm;
    if let Some(conn) = state.link.connected_mut() {
        conn.session
            .complete_write(state.now.instant, write_id.0, success);
    }
}

pub fn close_session(fsm: &mut QlFsm, code: SessionCloseCode) {
    let QlFsm { state, events, .. } = fsm;
    let Some(conn) = state.link.connected_mut() else {
        return;
    };
    let mut emit = FsmEventEmitter { events };
    conn.session.close(code, &mut emit);
}

pub fn open_stream(
    fsm: &mut QlFsm,
    route_id: RouteId,
) -> Result<crate::StreamOps<'_>, NoSessionError> {
    let QlFsm { state, events, .. } = fsm;
    let conn = state.link.connected_mut_or_err()?;
    let inner = conn
        .session
        .open_stream(route_id, FsmEventEmitter { events })?;
    Ok(crate::StreamOps { inner })
}

pub fn stream(fsm: &mut QlFsm, stream_id: StreamId) -> Result<crate::StreamOps<'_>, StreamError> {
    let QlFsm { state, events, .. } = fsm;
    let conn = state.link.connected_mut_or_err()?;
    let inner = conn.session.stream(stream_id, FsmEventEmitter { events })?;
    Ok(crate::StreamOps { inner })
}

pub fn queue_ping(fsm: &mut QlFsm) -> Result<(), NoSessionError> {
    let conn = fsm.state.link.connected_mut_or_err()?;
    conn.session.queue_ping()
}

pub fn poll_event(fsm: &mut QlFsm) -> Option<Event> {
    fsm.events.pop_front()
}

pub fn emit_peer_status(fsm: &mut QlFsm) {
    if fsm.state.peer.is_some() {
        fsm.events
            .push_back(Event::PeerStatusChanged(fsm.state.link.status()));
    }
}

fn apply_session_closed(fsm: &mut QlFsm) {
    if matches!(fsm.state.link, LinkState::Connected(_)) {
        fsm.state.link = LinkState::Idle;
        emit_peer_status(fsm);
    }
}

pub(super) fn deadline_after_secs(now_secs: u64, duration: Duration) -> u64 {
    now_secs.saturating_add(duration_to_secs(duration))
}

fn duration_to_secs(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
}
