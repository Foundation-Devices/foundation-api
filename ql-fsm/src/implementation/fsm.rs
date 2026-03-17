use std::time::Instant;

use ql_wire::{
    self as wire, handshake::ArchivedHandshakeRecord, ArchivedQlPayload, CloseCode, CloseTarget,
    Nonce, QlCrypto, QlHeader, StreamId,
};

use crate::{OutboundWrite, QlFsm, QlFsmError, QlFsmEvent, QlSessionEvent, SessionWriteId};

pub fn receive(
    fsm: &mut QlFsm,
    mut bytes: Vec<u8>,
    crypto: &impl QlCrypto,
) -> Result<(), QlFsmError> {
    let archived = wire::access_record_mut(&mut bytes)?;
    let archived = unsafe { archived.unseal_unchecked() };
    let header: QlHeader = super::deserialize_archived(&archived.header)?;

    if header.recipient != fsm.identity.xid {
        return Ok(());
    }
    if !matches!(&archived.payload, ArchivedQlPayload::Pair(_)) {
        let Some(peer) = fsm.peer.as_ref().map(|entry| entry.peer.xid) else {
            return Ok(());
        };
        if header.sender != peer {
            return Ok(());
        }
    }

    match &mut archived.payload {
        ArchivedQlPayload::Pair(request) => {
            super::handle_pair(fsm, crypto, &header, request)?;
        }
        ArchivedQlPayload::Handshake(ArchivedHandshakeRecord::Hello(archived_hello)) => {
            super::handle_hello(fsm, crypto, &header, archived_hello)?;
        }
        ArchivedQlPayload::Handshake(ArchivedHandshakeRecord::HelloReply(archived_reply)) => {
            super::handle_hello_reply(fsm, crypto, &header, archived_reply)?;
        }
        ArchivedQlPayload::Handshake(ArchivedHandshakeRecord::Confirm(archived_confirm)) => {
            super::handle_confirm(fsm, crypto, &header, archived_confirm)?;
        }
        ArchivedQlPayload::Handshake(ArchivedHandshakeRecord::Ready(archived_ready)) => {
            super::handle_ready(fsm, crypto, &header, archived_ready)?;
        }
        ArchivedQlPayload::Encrypted(encrypted) => {
            let Some((_, session_key)) = super::peer_session(fsm) else {
                return Ok(());
            };
            let envelope =
                match wire::encrypted::decrypt_record(crypto, &header, encrypted, &session_key) {
                    Ok(envelope) => envelope,
                    Err(_) => return Ok(()),
                };
            fsm.session.receive(fsm.state.now.instant, envelope);
            super::drain_session_events(fsm);
        }
    }

    Ok(())
}

pub fn on_timer(fsm: &mut QlFsm) {
    super::handle_timer(fsm);
    if super::peer_session(fsm).is_some() {
        fsm.session.on_timer(fsm.state.now.instant);
        super::drain_session_events(fsm);
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

    let (recipient, session_key) = super::peer_session(fsm)?;
    let envelope = fsm.session.take_next_write(fsm.state.now.instant)?;
    let mut nonce = [0u8; Nonce::NONCE_SIZE];
    crypto.fill_random_bytes(&mut nonce);
    Some(OutboundWrite {
        record: wire::encrypted::encrypt_record(
            crypto,
            QlHeader {
                sender: fsm.identity.xid,
                recipient,
            },
            &session_key,
            &envelope,
            Nonce(nonce),
        )
        .ok()?,
        session_write_id: Some(SessionWriteId(envelope.seq)),
    })
}

pub fn confirm_session_write(fsm: &mut QlFsm, write_id: SessionWriteId) {
    fsm.session.confirm_write(fsm.state.now.instant, write_id.0);
}

pub fn return_session_write(fsm: &mut QlFsm, write_id: SessionWriteId) {
    fsm.session.return_write(write_id.0);
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
    fsm.session.open_stream().map_err(Into::into)
}

pub fn write_stream(
    fsm: &mut QlFsm,
    stream_id: StreamId,
    bytes: Vec<u8>,
) -> Result<(), QlFsmError> {
    ensure_peer_bound(fsm)?;
    fsm.session
        .write_stream(stream_id, bytes)
        .map_err(Into::into)
}

pub fn finish_stream(fsm: &mut QlFsm, stream_id: StreamId) -> Result<(), QlFsmError> {
    ensure_peer_bound(fsm)?;
    fsm.session.finish_stream(stream_id).map_err(Into::into)
}

pub fn close_stream(
    fsm: &mut QlFsm,
    stream_id: StreamId,
    target: CloseTarget,
    code: CloseCode,
    payload: Vec<u8>,
) -> Result<(), QlFsmError> {
    ensure_peer_bound(fsm)?;
    fsm.session
        .close_stream(stream_id, target, code, payload)
        .map_err(Into::into)
}

pub fn queue_ping(fsm: &mut QlFsm) -> Result<(), QlFsmError> {
    ensure_session_open(fsm)?;
    fsm.session.queue_ping().map_err(Into::into)
}

pub fn queue_unpair(fsm: &mut QlFsm) -> Result<(), QlFsmError> {
    ensure_session_open(fsm)?;
    // TODO: keep local peer/session state alive until this queued unpair is acked or times out,
    // then clear it locally. Right now this only requests remote unpair.
    fsm.session.queue_unpair().map_err(Into::into)
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
