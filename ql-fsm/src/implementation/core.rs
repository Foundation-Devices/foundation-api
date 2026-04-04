use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use ql_wire::{
    self as wire, CloseTarget, QlCrypto, SessionClose, SessionCloseCode, SessionHeader,
    StreamCloseCode, StreamId, WireParse,
};

use crate::{
    session::{stream_parity::StreamParity, SessionEvent, SessionFsmConfig},
    state::LinkState,
    OutboundWrite, QlFsm, QlFsmError, QlFsmEvent, QlSessionEvent, SessionWriteId, StreamReadIter,
};

pub fn handle_bind_peer(fsm: &mut QlFsm, peer: ql_wire::PeerBundle) {
    fsm.state.handshake = None;
    fsm.state.link = LinkState::Idle;
    fsm.state.peer = Some(peer.clone());
    reset_session(fsm);
    fsm.state.events.push_back(QlFsmEvent::NewPeer(peer));
    emit_peer_status(fsm);
}

pub fn receive(
    fsm: &mut QlFsm,
    mut bytes: Vec<u8>,
    crypto: &impl QlCrypto,
) -> Result<(), QlFsmError> {
    let header = wire::RecordHeader::parse_prefix(bytes.as_slice())?;
    match header.record_type {
        wire::RecordType::Handshake => {
            let record = wire::QlHandshakeRecord::parse_bytes(bytes.as_slice())?;
            super::handle_handshake_record(fsm, crypto, &record)
        }
        wire::RecordType::Session => {
            let record = wire::QlSessionRecord::parse_bytes(&mut bytes[..])?;
            let transport = fsm.state.link.transport().ok_or(QlFsmError::NoSession)?;
            if record.header.connection_id != transport.rx_connection_id {
                return Err(QlFsmError::InvalidPayload);
            }

            let plaintext =
                wire::decrypt_record(crypto, &record.header, record.payload, &transport.rx_key)?;
            let frames = wire::SessionRecord::parse(plaintext)?;
            let mut session_closed = false;
            fsm.session
                .receive(fsm.state.now.instant, record.header.seq, frames, {
                    let session_events = &mut fsm.state.session_events;
                    |event| {
                        session_closed |= forward_session_event(session_events, event);
                    }
                });
            if session_closed {
                apply_session_closed(fsm);
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
                session_closed |= forward_session_event(session_events, event);
            }
        });
        if session_closed {
            apply_session_closed(fsm);
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
            record: record.encode(),
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
        record,
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
    emit_peer_status(fsm);
    reset_session(fsm);
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
    Ok(fsm.session.write_stream(stream_id, bytes)?)
}

pub fn stream_read(fsm: &QlFsm, stream_id: StreamId) -> Option<StreamReadIter<'_>> {
    fsm.session.stream_read(stream_id)
}

pub fn stream_read_commit(
    fsm: &mut QlFsm,
    stream_id: StreamId,
    len: usize,
) -> Result<(), QlFsmError> {
    Ok(fsm.session.stream_read_commit(stream_id, len)?)
}

pub fn stream_available_bytes(fsm: &QlFsm, stream_id: StreamId) -> Option<usize> {
    fsm.session.stream_available_bytes(stream_id)
}

pub fn finish_stream(fsm: &mut QlFsm, stream_id: StreamId) -> Result<(), QlFsmError> {
    Ok(fsm.session.finish_stream(stream_id)?)
}

pub fn close_stream(
    fsm: &mut QlFsm,
    stream_id: StreamId,
    target: CloseTarget,
    code: StreamCloseCode,
) -> Result<(), QlFsmError> {
    Ok(fsm.session.close_stream(stream_id, target, code)?)
}

pub fn queue_ping(fsm: &mut QlFsm) -> Result<(), QlFsmError> {
    ensure_session_open(fsm)?;
    Ok(fsm.session.queue_ping()?)
}

pub fn emit_peer_status(fsm: &mut QlFsm) {
    if let Some(peer) = fsm.state.peer.as_ref() {
        fsm.state.events.push_back(QlFsmEvent::PeerStatusChanged {
            peer: peer.xid,
            status: fsm.state.link.status(),
        });
    }
}

pub fn reset_session(fsm: &mut QlFsm) {
    let local_parity = fsm.state.peer.as_ref().map_or(StreamParity::Even, |peer| {
        StreamParity::for_local(fsm.identity.xid, peer.xid)
    });
    fsm.session = crate::session::SessionFsm::new(
        SessionFsmConfig {
            local_parity,
            record_target_size: fsm.config.session_record_target_size,
            record_max_size: fsm.config.session_record_max_size,
            ack_delay: fsm.config.session_record_ack_delay,
            retransmit_timeout: fsm.config.session_record_retransmit_timeout,
            keepalive_interval: fsm.config.session_keepalive_interval,
            peer_timeout: fsm.config.session_peer_timeout,
            stream_send_buffer_size: fsm.config.session_stream_send_buffer_size,
            stream_receive_buffer_size: fsm.config.session_stream_receive_buffer_size,
            initial_peer_stream_receive_window: fsm
                .state
                .link
                .transport()
                .map(|transport| {
                    transport
                        .remote_transport_params
                        .initial_stream_receive_window
                })
                .unwrap_or(fsm.config.session_stream_receive_buffer_size as u32),
        },
        fsm.state.now.instant,
    );
}

fn forward_session_event(
    session_events: &mut VecDeque<QlSessionEvent>,
    event: SessionEvent,
) -> bool {
    match event {
        SessionEvent::Opened(stream_id) => {
            session_events.push_back(QlSessionEvent::Opened(stream_id));
            false
        }
        SessionEvent::Readable(stream_id) => {
            session_events.push_back(QlSessionEvent::Readable(stream_id));
            false
        }
        SessionEvent::Writable(stream_id) => {
            session_events.push_back(QlSessionEvent::Writable(stream_id));
            false
        }
        SessionEvent::Finished(stream_id) => {
            session_events.push_back(QlSessionEvent::Finished(stream_id));
            false
        }
        SessionEvent::Closed(frame) => {
            session_events.push_back(QlSessionEvent::Closed(frame));
            false
        }
        SessionEvent::WritableClosed(stream_id) => {
            session_events.push_back(QlSessionEvent::WritableClosed(stream_id));
            false
        }
        SessionEvent::SessionClosed(close) => {
            session_events.push_back(QlSessionEvent::SessionClosed(close));
            true
        }
    }
}

fn apply_session_closed(fsm: &mut QlFsm) {
    if matches!(fsm.state.link, crate::state::LinkState::Connected(_)) {
        fsm.state.link = crate::state::LinkState::Idle;
        emit_peer_status(fsm);
    }
    reset_session(fsm);
}

fn ensure_session_open(fsm: &QlFsm) -> Result<(), QlFsmError> {
    fsm.state.ensure_peer_bound()?;
    if fsm.state.link.transport().is_none() {
        return Err(QlFsmError::SessionClosed);
    }
    Ok(())
}

pub(super) fn deadline_after_secs(now_secs: u64, duration: Duration) -> u64 {
    now_secs.saturating_add(duration_to_secs(duration))
}

fn duration_to_secs(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
}
