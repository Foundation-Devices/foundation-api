mod fsm;
mod handshake;
mod peer;

use std::time::Duration;

pub use fsm::*;
pub use handshake::*;
pub use peer::*;
use ql_wire::{ControlId, ControlMeta, QlHeader, QlPayload, QlRecord, SessionKey, XID};

use crate::{
    session::{SessionEvent, SessionFsmConfig, StreamNamespace},
    QlFsm, QlFsmEvent, QlSessionEvent,
};

fn emit_peer_status(fsm: &mut QlFsm) {
    if let Some(entry) = fsm.peer.as_ref() {
        fsm.state.events.push_back(QlFsmEvent::PeerStatusChanged {
            peer: entry.peer.xid,
            status: entry.session.status(),
        });
    }
}

fn next_control_meta(fsm: &mut QlFsm, lifetime: Duration) -> ControlMeta {
    let control_id = ControlId(fsm.state.next_control_id);
    fsm.state.next_control_id = fsm.state.next_control_id.wrapping_add(1);
    ControlMeta {
        control_id,
        valid_until: deadline_after_secs(fsm.state.now.unix_secs, lifetime),
    }
}

fn enqueue_handshake(fsm: &mut QlFsm, peer: XID, payload: QlPayload) {
    fsm.state.outbound.push_back(QlRecord {
        header: QlHeader {
            sender: fsm.identity.xid,
            recipient: peer,
        },
        payload,
    });
}

fn is_replayed_control(fsm: &mut QlFsm, peer: XID, meta: ControlMeta) -> bool {
    fsm.state
        .replay_cache
        .check_and_store_valid_until(peer, meta, fsm.state.now.unix_secs)
}

fn peer_session(fsm: &QlFsm) -> Option<(XID, SessionKey)> {
    let entry = fsm.peer.as_ref()?;
    let session_key = *entry.session.session_key()?;
    Some((entry.peer.xid, session_key))
}

fn reset_session(fsm: &mut QlFsm) {
    let local_namespace = fsm
        .peer
        .as_ref()
        .map(|peer| StreamNamespace::for_local(fsm.identity.xid, peer.peer.xid))
        .unwrap_or(StreamNamespace::Low);
    fsm.session = crate::session::SessionFsm::new(
        SessionFsmConfig {
            local_namespace,
            stream_chunk_size: fsm.config.session_stream_chunk_size,
            ack_delay: fsm.config.session_ack_delay,
            retransmit_timeout: fsm.config.session_retransmit_timeout,
            keepalive_interval: fsm.config.session_keepalive_interval,
            peer_timeout: fsm.config.session_peer_timeout,
        },
        fsm.state.now.instant,
    );
}

fn fail_pending_connect_session(fsm: &mut QlFsm, code: ql_wire::CloseCode) {
    if !fsm.session.has_pending_stream_work() {
        return;
    }
    reset_session(fsm);
    fsm.state
        .session_events
        .push_back(QlSessionEvent::SessionClosed(ql_wire::SessionCloseBody {
            code,
        }));
}

fn drain_session_events(fsm: &mut QlFsm) {
    while let Some(event) = fsm.session.take_next_event() {
        match event {
            SessionEvent::Opened(stream_id) => {
                fsm.state
                    .session_events
                    .push_back(QlSessionEvent::Opened(stream_id));
            }
            SessionEvent::Readable(stream_id) => {
                fsm.state
                    .session_events
                    .push_back(QlSessionEvent::Readable(stream_id));
            }
            SessionEvent::Finished(stream_id) => fsm
                .state
                .session_events
                .push_back(QlSessionEvent::Finished(stream_id)),
            SessionEvent::Closed(frame) => fsm
                .state
                .session_events
                .push_back(QlSessionEvent::Closed(frame)),
            SessionEvent::WritableClosed(stream_id) => {
                fsm.state
                    .session_events
                    .push_back(QlSessionEvent::WritableClosed(stream_id));
            }
            SessionEvent::Unpaired => {
                fsm.state.session_events.push_back(QlSessionEvent::Unpaired);
                fsm.peer = None;
                reset_session(fsm);
                fsm.state.events.push_back(QlFsmEvent::ClearPeer);
            }
            SessionEvent::SessionClosed(close) => {
                fsm.state
                    .session_events
                    .push_back(QlSessionEvent::SessionClosed(close.clone()));
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
        }
    }
}

fn deadline_after_secs(now_secs: u64, duration: Duration) -> u64 {
    now_secs.saturating_add(duration_to_secs(duration))
}

fn duration_to_secs(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
}
