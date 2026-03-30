mod fsm;
mod handshake;

use std::{collections::VecDeque, time::Duration};

pub use fsm::*;
pub use handshake::*;
use ql_wire::XID;

use crate::{
    state::PeerRecord,
    session::{state::StreamParity, SessionEvent, SessionFsmConfig},
    Peer, QlFsm, QlFsmEvent, QlSessionEvent,
};

fn emit_peer_status(fsm: &mut QlFsm) {
    if let Some(entry) = fsm.peer.as_ref() {
        fsm.state.events.push_back(QlFsmEvent::PeerStatusChanged {
            peer: entry.peer.xid,
            status: entry.session.status(),
        });
    }
}

fn peer_transport(fsm: &QlFsm) -> Option<(XID, crate::state::SessionTransport)> {
    let entry = fsm.peer.as_ref()?;
    let transport = entry.session.transport()?.clone();
    Some((entry.peer.xid, transport))
}

fn reset_session(fsm: &mut QlFsm) {
    let local_parity = fsm
        .peer
        .as_ref()
        .map(|peer| StreamParity::for_local(fsm.identity.xid, peer.peer.xid))
        .unwrap_or(StreamParity::Even);
    fsm.session = crate::session::SessionFsm::new(
        SessionFsmConfig {
            local_parity,
            record_size: fsm.config.session_record_size,
            ack_delay: fsm.config.session_record_ack_delay,
            retransmit_timeout: fsm.config.session_record_retransmit_timeout,
            keepalive_interval: fsm.config.session_keepalive_interval,
            peer_timeout: fsm.config.session_peer_timeout,
            stream_send_buffer_size: fsm.config.session_stream_send_buffer_size,
            stream_receive_buffer_size: fsm.config.session_stream_receive_buffer_size,
        },
        fsm.state.now.instant,
    );
}

pub fn handle_bind_peer(fsm: &mut QlFsm, peer: Peer) {
    fsm.state.handshake = None;
    fsm.peer = Some(PeerRecord::new(peer.clone()));
    reset_session(fsm);
    fsm.state.events.push_back(QlFsmEvent::NewPeer(peer));
    emit_peer_status(fsm);
}

fn fail_pending_connect_session(fsm: &mut QlFsm, code: ql_wire::SessionCloseCode) {
    if !fsm.session.has_pending_stream_work() {
        return;
    }
    reset_session(fsm);
    fsm.state
        .session_events
        .push_back(QlSessionEvent::SessionClosed(ql_wire::SessionClose { code }));
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
    if let Some(entry) = fsm.peer.as_mut() {
        if matches!(
            entry.session,
            crate::state::ConnectionState::Connected { .. }
        ) {
            entry.session = crate::state::ConnectionState::Disconnected;
            emit_peer_status(fsm);
        }
    }
    reset_session(fsm);
}

fn deadline_after_secs(now_secs: u64, duration: Duration) -> u64 {
    now_secs.saturating_add(duration_to_secs(duration))
}

fn duration_to_secs(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
}
