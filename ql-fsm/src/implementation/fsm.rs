use std::time::Instant;

use ql_wire::{self as wire, CloseCode, CloseTarget, Nonce, QlCrypto, QlPayloadRef, StreamId};

use crate::{
    OutboundWrite, QlFsm, QlFsmError, QlFsmEvent, QlSessionEvent, SessionWriteId, StreamReadIter,
};

pub fn receive(
    fsm: &mut QlFsm,
    mut bytes: Vec<u8>,
    crypto: &impl QlCrypto,
) -> Result<(), QlFsmError> {
    let wire::QlRecordRef { header, payload } = wire::QlRecord::parse_mut(&mut bytes)?;

    if header.recipient != fsm.identity.xid {
        return Err(QlFsmError::InvalidXid);
    }
    match &payload {
        QlPayloadRef::PairRequest(_) => {}
        QlPayloadRef::Unpair(_) => {
            let Some(peer) = fsm.peer.as_ref().map(|entry| entry.peer.xid) else {
                return Ok(());
            };
            if header.sender != peer {
                return Err(QlFsmError::InvalidXid);
            }
        }
        _ => {
            let Some(peer) = fsm.peer.as_ref().map(|entry| entry.peer.xid) else {
                return Err(QlFsmError::NoPeerBound);
            };
            if header.sender != peer {
                return Err(QlFsmError::InvalidXid);
            }
        }
    }

    match payload {
        QlPayloadRef::PairRequest(request) => {
            super::handle_pair(fsm, crypto, &header, request)?;
        }
        QlPayloadRef::Unpair(unpair) => {
            super::handle_unpair(fsm, crypto, &header, &unpair)?;
        }
        QlPayloadRef::Hello(hello) => {
            super::handle_hello(fsm, crypto, &header, &hello)?;
        }
        QlPayloadRef::HelloReply(reply) => {
            super::handle_hello_reply(fsm, crypto, &header, &reply)?;
        }
        QlPayloadRef::Confirm(confirm) => {
            super::handle_confirm(fsm, crypto, &header, &confirm)?;
        }
        QlPayloadRef::Ready(ready) => {
            super::handle_ready(fsm, crypto, &header, ready)?;
        }
        QlPayloadRef::Session(encrypted) => {
            let Some((_, session_key)) = super::peer_session(fsm) else {
                return Err(QlFsmError::NoSession);
            };
            let plaintext = wire::decrypt_record(crypto, &header, encrypted, &session_key)?;
            let (seq, frames) = wire::SessionRecord::parse(plaintext.as_ref())?;
            let mut session_closed = false;
            fsm.session.receive(fsm.state.now.instant, seq, frames, {
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

    Ok(())
}

pub fn on_timer(fsm: &mut QlFsm) {
    super::handle_timer(fsm);
    if super::peer_session(fsm).is_some() {
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
        super::peer_session(fsm).and_then(|_| fsm.session.next_deadline()),
    ]
    .into_iter()
    .flatten()
    .min()
}

pub fn take_next_write(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Option<OutboundWrite> {
    if let Some(record) = fsm.state.outbound.pop_front() {
        return Some(OutboundWrite {
            record,
            session_write_id: None,
        });
    }

    if matches!(
        fsm.peer.as_ref().map(|entry| &entry.session),
        Some(crate::state::ConnectionState::Disconnected)
    ) && fsm.session.has_pending_stream_work()
    {
        let _ = super::handle_connect(fsm, crypto);
        if let Some(record) = fsm.state.outbound.pop_front() {
            return Some(OutboundWrite {
                record,
                session_write_id: None,
            });
        }
    }

    let sender = fsm.identity.xid;
    let (recipient, session_key) = super::peer_session(fsm)?;
    let (write_id, builder) = fsm.session.take_next_write(fsm.state.now.instant)?;
    let mut nonce = [0u8; Nonce::SIZE];
    crypto.fill_random_bytes(&mut nonce);
    Some(OutboundWrite {
        record: builder.encrypt(
            crypto,
            wire::QlHeader { sender, recipient },
            &session_key,
            Nonce(nonce),
        ),
        session_write_id: Some(SessionWriteId(write_id)),
    })
}

pub fn confirm_session_write(fsm: &mut QlFsm, write_id: SessionWriteId) {
    fsm.session.confirm_write(fsm.state.now.instant, write_id.0);
}

pub fn reject_session_write(fsm: &mut QlFsm, write_id: SessionWriteId) {
    fsm.session.reject_write(write_id.0);
}

pub fn kill_session(fsm: &mut QlFsm, code: CloseCode) {
    let Some(entry) = fsm.peer.as_mut() else {
        return;
    };
    if !matches!(
        entry.session,
        crate::state::ConnectionState::Connected { .. }
    ) {
        return;
    }

    entry.session = crate::state::ConnectionState::Disconnected;
    super::emit_peer_status(fsm);
    super::reset_session(fsm);
    fsm.state
        .session_events
        .push_back(QlSessionEvent::SessionClosed(ql_wire::SessionCloseBody {
            code,
        }));
}

pub fn take_next_event(fsm: &mut QlFsm) -> Option<QlFsmEvent> {
    fsm.state.events.pop_front()
}

pub fn take_next_session_event(fsm: &mut QlFsm) -> Option<QlSessionEvent> {
    fsm.state.session_events.pop_front()
}

pub fn open_stream(fsm: &mut QlFsm) -> Result<StreamId, QlFsmError> {
    ensure_peer_bound(fsm)?;
    Ok(fsm.session.open_stream()?)
}

pub fn write_stream(
    fsm: &mut QlFsm,
    stream_id: StreamId,
    bytes: &[u8],
) -> Result<usize, QlFsmError> {
    ensure_peer_bound(fsm)?;
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
    ensure_peer_bound(fsm)?;
    Ok(fsm.session.finish_stream(stream_id)?)
}

pub fn close_stream(
    fsm: &mut QlFsm,
    stream_id: StreamId,
    target: CloseTarget,
    code: CloseCode,
    payload: Vec<u8>,
) -> Result<(), QlFsmError> {
    ensure_peer_bound(fsm)?;
    Ok(fsm.session.close_stream(stream_id, target, code, payload)?)
}

pub fn queue_ping(fsm: &mut QlFsm) -> Result<(), QlFsmError> {
    ensure_session_open(fsm)?;
    Ok(fsm.session.queue_ping()?)
}

pub fn unpair(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Option<wire::QlRecord> {
    super::handle_unpair_local(fsm, crypto)
}

fn ensure_peer_bound(fsm: &QlFsm) -> Result<(), QlFsmError> {
    fsm.peer.as_ref().map(|_| ()).ok_or(QlFsmError::NoPeerBound)
}

fn ensure_session_open(fsm: &QlFsm) -> Result<(), QlFsmError> {
    ensure_peer_bound(fsm)?;
    if fsm
        .peer
        .as_ref()
        .and_then(|entry| entry.session.session_key())
        .is_none()
    {
        return Err(QlFsmError::SessionClosed);
    }
    Ok(())
}
