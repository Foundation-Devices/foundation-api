mod ik;
mod kk;

use ql_wire::{self as wire, EphemeralPublicKey, HandshakeMeta, QlCrypto, QlHandshakeRecord};

use super::emit_peer_status;
use crate::{
    session::{stream_parity::StreamParity, SessionFsm, SessionFsmConfig},
    state::{ConnectedState, LinkState, SessionTransport},
    QlFsm, QlFsmError, QlFsmEvent,
};

pub fn handle_connect_ik(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
    let peer = fsm.state.peer.clone().ok_or(QlFsmError::NoPeerBound)?;
    prepare_for_outbound_connect(fsm);
    ik::start_initiator(fsm, crypto, peer)
}

pub fn handle_connect_kk(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
    let peer = fsm.state.peer.clone().ok_or(QlFsmError::NoPeerBound)?;
    prepare_for_outbound_connect(fsm);
    kk::start_initiator(fsm, crypto, peer)
}

pub fn next_handshake_meta(fsm: &mut QlFsm) -> HandshakeMeta {
    let handshake_id = wire::HandshakeId(fsm.state.next_control_id);
    fsm.state.next_control_id = fsm.state.next_control_id.wrapping_add(1);
    HandshakeMeta {
        handshake_id,
        valid_until: super::deadline_after_secs(
            fsm.state.now.unix_secs,
            fsm.config.handshake_timeout,
        ),
    }
}

pub fn enqueue_handshake(fsm: &mut QlFsm, record: QlHandshakeRecord) {
    debug_assert!(fsm.state.handshake.is_none());
    fsm.state.handshake = Some(record);
}

fn local_transport_params(fsm: &QlFsm) -> wire::TransportParams {
    wire::TransportParams {
        initial_stream_receive_window: fsm.config.session_stream_receive_buffer_size,
    }
}

pub fn prepare_for_outbound_connect(fsm: &mut QlFsm) {
    fsm.state.handshake = None;
    reset_connected_session_if_needed(fsm);
}

pub fn is_replayed_handshake_start(fsm: &mut QlFsm, meta: HandshakeMeta) -> bool {
    fsm.state
        .replay_cache
        .check_and_store_valid_until(meta, fsm.state.now.unix_secs)
}

pub fn handle_handshake_record(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    record: &QlHandshakeRecord,
) -> Result<(), QlFsmError> {
    match record {
        QlHandshakeRecord::Ik1(message) => ik::handle_ik1(fsm, crypto, message),
        QlHandshakeRecord::Ik2(message) => ik::handle_ik2(fsm, crypto, message),
        QlHandshakeRecord::Kk1(message) => kk::handle_kk1(fsm, crypto, message),
        QlHandshakeRecord::Kk2(message) => kk::handle_kk2(fsm, crypto, message),
    }
}

pub fn handle_timer(fsm: &mut QlFsm) {
    let Some(deadline) = fsm.state.link.handshake_deadline() else {
        return;
    };
    if deadline > fsm.state.now.instant {
        return;
    }

    fsm.state.link = LinkState::Idle;
    fsm.state.handshake = None;
    emit_peer_status(fsm);
}

pub fn next_handshake_deadline(fsm: &QlFsm) -> Option<std::time::Instant> {
    fsm.state.link.handshake_deadline()
}

pub fn finish_handshake(
    fsm: &mut QlFsm,
    transport: SessionTransport,
    remote_bundle: &wire::PeerBundle,
) -> Result<(), QlFsmError> {
    if let Some(peer) = fsm.state.peer.as_ref() {
        if peer != remote_bundle {
            return Err(QlFsmError::InvalidPayload);
        }
    } else {
        fsm.state.peer = Some(remote_bundle.clone());
        fsm.state
            .events
            .push_back(QlFsmEvent::NewPeer(remote_bundle.clone()));
    }

    let config = &fsm.config;
    let session = SessionFsm::new(
        SessionFsmConfig {
            local_parity: StreamParity::for_local(fsm.identity.xid, remote_bundle.xid),
            record_max_size: config.session_record_max_size,
            ack_delay: config.session_record_ack_delay,
            retransmit_timeout: config.session_record_retransmit_timeout,
            keepalive_interval: config.session_keepalive_interval,
            peer_timeout: config.session_peer_timeout,
            stream_send_buffer_size: config.session_stream_send_buffer_size,
            stream_receive_buffer_size: config.session_stream_receive_buffer_size,
            initial_peer_stream_receive_window: transport
                .remote_transport_params
                .initial_stream_receive_window,
        },
        fsm.state.now.instant,
    );
    fsm.state.link = LinkState::Connected(ConnectedState { transport, session });
    emit_peer_status(fsm);
    Ok(())
}

pub fn reset_connected_session_if_needed(fsm: &mut QlFsm) {
    if matches!(fsm.state.link, LinkState::Connected(_)) {
        fsm.state.link = LinkState::Idle;
    }
}

fn local_start_wins(local: &EphemeralPublicKey, inbound: &EphemeralPublicKey) -> bool {
    local.mlkem_public_key.as_bytes() <= inbound.mlkem_public_key.as_bytes()
}
