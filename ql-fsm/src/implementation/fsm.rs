use std::time::Instant;

use ql_wire::{
    self as wire, CloseTarget, QlCrypto, SessionClose, SessionCloseCode, SessionHeader,
    StreamCloseCode, StreamId,
};

use crate::{OutboundWrite, QlFsm, QlFsmError, QlSessionEvent, SessionWriteId, StreamReadIter};

pub fn receive(
    fsm: &mut QlFsm,
    mut bytes: Vec<u8>,
    crypto: &impl QlCrypto,
) -> Result<(), QlFsmError> {
    match wire::QlRecord::parse(&mut bytes[..])? {
        wire::QlRecord::Handshake(record) => super::handle_handshake_record(fsm, crypto, &record),
        wire::QlRecord::Session(record) => {
            let transport = fsm.state.link.transport().ok_or(QlFsmError::NoSession)?;
            if record.header.connection_id != transport.rx_connection_id {
                return Err(QlFsmError::InvalidPayload);
            }

            let plaintext =
                wire::decrypt_record(crypto, &record.header, record.payload, &transport.rx_key)?;
            let frames = wire::SessionRecord::parse(plaintext.as_ref())?;
            let mut session_closed = false;
            fsm.session
                .receive(fsm.state.now.instant, record.header.seq, frames, {
                    let session_events = &mut fsm.state.session_events;
                    |event| {
                        session_closed |= super::forward_session_event(session_events, event);
                    }
                });
            if session_closed {
                super::apply_session_closed(fsm);
            }
            Ok(())
        }
    }
}

pub fn on_timer(fsm: &mut QlFsm) {
    super::handle_timer(fsm);
    if fsm.state.link.transport().is_some() {
        let mut session_closed = false;
        fsm.session.on_timer(fsm.state.now.instant, {
            let session_events = &mut fsm.state.session_events;
            |event| {
                session_closed |= super::forward_session_event(session_events, event);
            }
        });
        if session_closed {
            super::apply_session_closed(fsm);
        }
    }
}

pub fn next_deadline(fsm: &QlFsm) -> Option<Instant> {
    [
        super::next_handshake_deadline(fsm),
        fsm.state
            .link
            .transport()
            .and_then(|_| fsm.session.next_deadline()),
    ]
    .into_iter()
    .flatten()
    .min()
}

pub fn take_next_write(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Option<OutboundWrite> {
    if let Some(record) = fsm.state.handshake.take() {
        return Some(OutboundWrite {
            record: wire::QlRecord::Handshake(record),
            session_write_id: None,
        });
    }
    // TODO: queued stream work now requires an explicit connect_ik() or connect_kk()
    // before any handshake or session bytes will be emitted.

    let transport = fsm.state.link.transport()?;
    let (write_id, seq, builder) = fsm.session.take_next_write(fsm.state.now.instant)?;
    let record = builder.encrypt(
        crypto,
        SessionHeader {
            connection_id: transport.tx_connection_id,
            seq,
        },
        &transport.tx_key,
    );
    Some(OutboundWrite {
        record: wire::QlRecord::Session(record),
        session_write_id: Some(SessionWriteId(write_id)),
    })
}

pub fn confirm_session_write(fsm: &mut QlFsm, write_id: SessionWriteId) {
    fsm.session.confirm_write(fsm.state.now.instant, write_id.0);
}

pub fn reject_session_write(fsm: &mut QlFsm, write_id: SessionWriteId) {
    fsm.session.reject_write(write_id.0);
}

pub fn kill_session(fsm: &mut QlFsm, code: SessionCloseCode) {
    if fsm.state.peer.is_none() {
        return;
    }
    if !matches!(fsm.state.link, crate::state::LinkState::Connected(_)) {
        return;
    }

    fsm.state.link = crate::state::LinkState::Idle;
    super::emit_peer_status(fsm);
    super::reset_session(fsm);
    fsm.state
        .session_events
        .push_back(QlSessionEvent::SessionClosed(SessionClose { code }));
}

pub fn open_stream(fsm: &mut QlFsm) -> Result<StreamId, QlFsmError> {
    fsm.state.ensure_peer_bound()?;
    Ok(fsm.session.open_stream()?)
}

pub fn write_stream(
    fsm: &mut QlFsm,
    stream_id: StreamId,
    bytes: &[u8],
) -> Result<usize, QlFsmError> {
    fsm.state.ensure_peer_bound()?;
    Ok(fsm.session.write_stream(stream_id, bytes)?)
}

pub fn stream_read(fsm: &QlFsm, stream_id: StreamId) -> Result<StreamReadIter<'_>, QlFsmError> {
    Ok(fsm.session.stream_read(stream_id)?)
}

pub fn stream_read_commit(
    fsm: &mut QlFsm,
    stream_id: StreamId,
    len: usize,
) -> Result<(), QlFsmError> {
    Ok(fsm.session.stream_read_commit(stream_id, len)?)
}

pub fn stream_available_bytes(fsm: &QlFsm, stream_id: StreamId) -> Result<usize, QlFsmError> {
    Ok(fsm.session.stream_available_bytes(stream_id)?)
}

pub fn finish_stream(fsm: &mut QlFsm, stream_id: StreamId) -> Result<(), QlFsmError> {
    fsm.state.ensure_peer_bound()?;
    Ok(fsm.session.finish_stream(stream_id)?)
}

pub fn close_stream(
    fsm: &mut QlFsm,
    stream_id: StreamId,
    target: CloseTarget,
    code: StreamCloseCode,
) -> Result<(), QlFsmError> {
    fsm.state.ensure_peer_bound()?;
    Ok(fsm.session.close_stream(stream_id, target, code)?)
}

pub fn queue_ping(fsm: &mut QlFsm) -> Result<(), QlFsmError> {
    ensure_session_open(fsm)?;
    Ok(fsm.session.queue_ping()?)
}

fn ensure_session_open(fsm: &QlFsm) -> Result<(), QlFsmError> {
    fsm.state.ensure_peer_bound()?;
    if fsm.state.link.transport().is_none() {
        return Err(QlFsmError::SessionClosed);
    }
    Ok(())
}
