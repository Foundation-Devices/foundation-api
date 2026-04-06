use std::time::{Duration, Instant};

use ql_wire::{
    self as wire, CloseTarget, QlCrypto, SessionCloseCode, StreamCloseCode, StreamId, WireParse,
};

use crate::{
    session::SessionEvent, state::LinkState, OutboundWrite, QlFsm, QlFsmError, QlFsmEvent,
    SessionWriteId, StreamReadIter,
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
    mut emit: impl FnMut(QlFsmEvent),
) -> Result<(), QlFsmError> {
    let header = wire::RecordHeader::parse_prefix(bytes.as_slice())?;
    match header.record_type {
        wire::RecordType::Handshake => {
            let record = wire::QlHandshakeRecord::parse_bytes(bytes.as_slice())?;
            super::handle_handshake_record(fsm, crypto, &record, &mut emit)
        }
        wire::RecordType::Session => {
            let record = wire::QlSessionRecord::parse_bytes(&mut bytes[..])?;
            let state = fsm.state.link.connected_mut_or_err()?;
            if record.header.connection_id != state.transport.rx_connection_id {
                return Err(QlFsmError::InvalidPayload);
            }
            let plaintext = wire::decrypt_record(
                crypto,
                &record.header,
                record.payload,
                &state.transport.rx_key,
            )?;
            let frames = wire::SessionRecord::parse(plaintext)?;

            let mut session_closed = false;
            state
                .session
                .receive(fsm.state.now.instant, record.header.seq, frames, |event| {
                    session_closed |= forward_session_event(event, &mut emit);
                });

            if session_closed {
                apply_session_closed(fsm, &mut emit);
            }
            Ok(())
        }
    }
}

pub fn on_timer(fsm: &mut QlFsm, mut emit: impl FnMut(QlFsmEvent)) {
    super::handle_timer(fsm, &mut emit);
    let Some(state) = fsm.state.link.connected_mut() else {
        return;
    };

    let mut session_closed = false;
    state.session.on_timer(fsm.state.now.instant, |event| {
        session_closed |= forward_session_event(event, &mut emit);
    });

    if session_closed {
        apply_session_closed(fsm, &mut emit);
    }
}

pub fn next_deadline(fsm: &QlFsm) -> Option<Instant> {
    [
        super::next_handshake_deadline(fsm),
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
        return Some(OutboundWrite {
            record: record.encode(),
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
    Some(OutboundWrite {
        record,
        session_write_id: write_id.map(SessionWriteId),
    })
}

pub fn confirm_session_write(fsm: &mut QlFsm, write_id: SessionWriteId) {
    if let Some(state) = fsm.state.link.connected_mut() {
        state
            .session
            .confirm_write(fsm.state.now.instant, write_id.0);
    }
}

pub fn reject_session_write(fsm: &mut QlFsm, write_id: SessionWriteId) {
    if let Some(state) = fsm.state.link.connected_mut() {
        state.session.reject_write(write_id.0);
    }
}

pub fn kill_session(fsm: &mut QlFsm, _code: SessionCloseCode) {
    if fsm.state.peer.is_none() {
        return;
    }
    if !matches!(fsm.state.link, crate::state::LinkState::Connected(_)) {
        return;
    }

    fsm.state.link = crate::state::LinkState::Idle;
}

pub fn open_stream(fsm: &mut QlFsm) -> Result<StreamId, QlFsmError> {
    let state = fsm.state.link.connected_mut_or_err()?;
    Ok(state.session.open_stream()?)
}

pub fn write_stream(
    fsm: &mut QlFsm,
    stream_id: StreamId,
    bytes: &[u8],
) -> Result<usize, QlFsmError> {
    let state = fsm.state.link.connected_mut_or_err()?;
    Ok(state.session.write_stream(stream_id, bytes)?)
}

pub fn stream_read(fsm: &QlFsm, stream_id: StreamId) -> Option<StreamReadIter<'_>> {
    fsm.state
        .link
        .connected()
        .and_then(|state| state.session.stream_read(stream_id))
}

pub fn stream_read_commit(
    fsm: &mut QlFsm,
    stream_id: StreamId,
    len: usize,
) -> Result<(), QlFsmError> {
    let state = fsm.state.link.connected_mut_or_err()?;
    Ok(state.session.stream_read_commit(stream_id, len)?)
}

pub fn stream_available_bytes(fsm: &QlFsm, stream_id: StreamId) -> Option<usize> {
    fsm.state
        .link
        .connected()
        .and_then(|state| state.session.stream_available_bytes(stream_id))
}

pub fn finish_stream(fsm: &mut QlFsm, stream_id: StreamId) -> Result<(), QlFsmError> {
    let state = fsm.state.link.connected_mut_or_err()?;
    Ok(state.session.finish_stream(stream_id)?)
}

pub fn close_stream(
    fsm: &mut QlFsm,
    stream_id: StreamId,
    target: CloseTarget,
    code: StreamCloseCode,
) -> Result<(), QlFsmError> {
    let state = fsm.state.link.connected_mut_or_err()?;
    Ok(state.session.close_stream(stream_id, target, code)?)
}

pub fn queue_ping(fsm: &mut QlFsm) -> Result<(), QlFsmError> {
    let state = fsm.state.link.connected_mut_or_err()?;
    Ok(state.session.queue_ping()?)
}

pub fn emit_peer_status(fsm: &QlFsm, emit: &mut impl FnMut(QlFsmEvent)) {
    if fsm.state.peer.is_some() {
        emit(QlFsmEvent::PeerStatusChanged(fsm.state.link.status()));
    }
}

fn forward_session_event(event: SessionEvent, emit: &mut impl FnMut(QlFsmEvent)) -> bool {
    match event {
        SessionEvent::Opened(stream_id) => {
            emit(QlFsmEvent::Opened(stream_id));
            false
        }
        SessionEvent::Readable(stream_id) => {
            emit(QlFsmEvent::Readable(stream_id));
            false
        }
        SessionEvent::Writable(stream_id) => {
            emit(QlFsmEvent::Writable(stream_id));
            false
        }
        SessionEvent::Finished(stream_id) => {
            emit(QlFsmEvent::Finished(stream_id));
            false
        }
        SessionEvent::Closed(frame) => {
            emit(QlFsmEvent::Closed(frame));
            false
        }
        SessionEvent::WritableClosed(stream_id) => {
            emit(QlFsmEvent::WritableClosed(stream_id));
            false
        }
        SessionEvent::SessionClosed(close) => {
            emit(QlFsmEvent::SessionClosed(close));
            true
        }
    }
}

fn apply_session_closed(fsm: &mut QlFsm, emit: &mut impl FnMut(QlFsmEvent)) {
    if matches!(fsm.state.link, crate::state::LinkState::Connected(_)) {
        fsm.state.link = crate::state::LinkState::Idle;
        emit_peer_status(fsm, emit);
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
