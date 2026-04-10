use std::time::{Duration, Instant};

use bytes::Bytes;
use ql_wire::{self as wire, QlCrypto, RouteId, SessionCloseCode, StreamId, WireDecode};

use crate::{
    handshake, session::SessionEvent, state::LinkState, Event, NoSessionError, OutboundWrite,
    QlFsm, ReceiveError, StreamError, StreamOps, WriteId,
};

pub fn handle_bind_peer(fsm: &mut QlFsm, peer: ql_wire::PeerBundle) {
    fsm.state.handshake = None;
    fsm.state.link = LinkState::Idle;
    fsm.state.peer = Some(peer);
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
            let state = fsm
                .state
                .link
                .connected_mut()
                .ok_or(ReceiveError::NoSession)?;
            let (decrypt_len, seq) = {
                let record = wire::QlSessionRecord::decode(&mut reader)?;
                if record.header.connection_id != state.transport.rx_connection_id {
                    return Err(ReceiveError::InvalidPayload);
                }
                let payload = wire::decrypt_record(
                    crypto,
                    &record.header,
                    record.payload,
                    &state.transport.rx_key,
                )?;
                (payload.len(), record.header.seq)
            };

            let len = bytes.len();
            let plaintext = Bytes::from(bytes).slice(len - decrypt_len..);
            let frames = wire::parse_session_frames(plaintext);

            state.session.receive(fsm.state.now.instant, seq, frames, {
                let pending_events = &mut fsm.pending_events;
                |event| {
                    forward_session_event(event, pending_events);
                }
            });

            if state.session.is_closed() {
                apply_session_closed(fsm);
            }
            Ok(())
        }
    }
}

pub fn on_timer(fsm: &mut QlFsm) {
    handshake::handle_timer(fsm);

    let Some(state) = fsm.state.link.connected_mut() else {
        return;
    };

    let pending_events = &mut fsm.pending_events;
    state.session.on_timer(fsm.state.now.instant, |event| {
        forward_session_event(event, pending_events);
    });

    if state.session.is_closed() {
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
            session_write_id: None,
        });
    }

    let state = fsm.state.link.connected_mut()?;
    let (write_id, builder) = state.session.take_next_write(fsm.state.now.instant)?;
    let record = builder.encrypt(
        crypto,
        state.transport.tx_connection_id,
        &state.transport.tx_key,
    );
    if state.session.is_closed() {
        apply_session_closed(fsm);
    }
    Some(OutboundWrite {
        record,
        session_write_id: write_id.map(WriteId),
    })
}

pub fn confirm_session_write(fsm: &mut QlFsm, write_id: WriteId) {
    if let Some(state) = fsm.state.link.connected_mut() {
        state
            .session
            .confirm_write(fsm.state.now.instant, write_id.0);
    }
}

pub fn reject_session_write(fsm: &mut QlFsm, write_id: WriteId) {
    if let Some(state) = fsm.state.link.connected_mut() {
        state.session.reject_write(write_id.0);
    }
}

pub fn close_session(fsm: &mut QlFsm, code: SessionCloseCode) {
    let Some(state) = fsm.state.link.connected_mut() else {
        return;
    };
    let pending_events = &mut fsm.pending_events;
    state.session.close(code, |event| {
        forward_session_event(event, pending_events);
    });
}

pub fn open_stream(fsm: &mut QlFsm, route_id: RouteId) -> Result<StreamOps<'_>, NoSessionError> {
    let state = fsm.state.link.connected_mut_or_err()?;
    state.session.open_stream(route_id)
}

pub fn stream(fsm: &mut QlFsm, stream_id: StreamId) -> Result<StreamOps<'_>, StreamError> {
    let state = fsm.state.link.connected_mut_or_err()?;
    state.session.stream(stream_id)
}

pub fn queue_ping(fsm: &mut QlFsm) -> Result<(), NoSessionError> {
    let state = fsm.state.link.connected_mut_or_err()?;
    state.session.queue_ping()
}

pub fn emit_peer_status(fsm: &mut QlFsm) {
    if fsm.state.peer.is_some() {
        fsm.pending_events
            .push_back(Event::PeerStatusChanged(fsm.state.link.status()));
    }
}

fn forward_session_event(
    event: SessionEvent,
    pending_events: &mut std::collections::VecDeque<Event>,
) {
    match event {
        SessionEvent::Opened {
            stream_id,
            route_id,
        } => {
            pending_events.push_back(Event::Opened {
                stream_id,
                route_id,
            });
        }
        SessionEvent::Readable(stream_id) => {
            pending_events.push_back(Event::Readable(stream_id));
        }
        SessionEvent::Writable(stream_id) => {
            pending_events.push_back(Event::Writable(stream_id));
        }
        SessionEvent::Finished(stream_id) => {
            pending_events.push_back(Event::Finished(stream_id));
        }
        SessionEvent::Closed(frame) => {
            pending_events.push_back(Event::Closed(frame));
        }
        SessionEvent::WritableClosed(frame) => {
            pending_events.push_back(Event::WritableClosed(frame));
        }
        SessionEvent::SessionClosed(close) => {
            pending_events.push_back(Event::SessionClosed(close));
        }
    }
}

fn apply_session_closed(fsm: &mut QlFsm) {
    if matches!(fsm.state.link, crate::state::LinkState::Connected(_)) {
        fsm.state.link = crate::state::LinkState::Idle;
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
