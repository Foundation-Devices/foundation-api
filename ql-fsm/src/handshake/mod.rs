mod ik;
mod kk;
mod xx;

use ql_wire::{
    self as wire, EphemeralPublicKey, HandshakeId, HandshakeMeta, QlCrypto, QlHandshakeRecord, QID,
};

use crate::{
    fsm::emit_peer_status,
    session::{SessionConfig, SessionFsm, StreamParity},
    state::{ConnectedState, LinkState, SessionTransport},
    Event, NoPeerError, QlFsm, ReceiveError,
};

pub fn handle_connect_ik(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Result<(), NoPeerError> {
    let peer = fsm.state.peer.clone().ok_or(NoPeerError)?;
    prepare_for_outbound_connect(fsm);
    ik::start_initiator(fsm, crypto, peer);
    Ok(())
}

pub fn handle_connect_kk(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Result<(), NoPeerError> {
    let peer = fsm.state.peer.clone().ok_or(NoPeerError)?;
    prepare_for_outbound_connect(fsm);
    kk::start_initiator(fsm, crypto, peer);
    Ok(())
}

pub fn handle_connect_xx(fsm: &mut QlFsm, invite: crate::PairingInvite, crypto: &impl QlCrypto) {
    prepare_for_outbound_connect(fsm);
    xx::start_initiator(fsm, crypto, invite.token, invite.qid);
}

pub fn next_handshake_meta(fsm: &mut QlFsm) -> HandshakeMeta {
    let handshake_id = wire::HandshakeId(fsm.state.next_control_id);
    fsm.state.next_control_id = fsm.state.next_control_id.wrapping_add(1);
    HandshakeMeta { handshake_id }
}

pub fn enqueue_handshake(fsm: &mut QlFsm, record: QlHandshakeRecord) {
    debug_assert!(fsm.state.handshake.is_none());
    fsm.state.handshake = Some(record);
}

pub fn handle_disarm_pairing(fsm: &mut QlFsm) {
    xx::disarm_pairing(fsm);
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

pub fn handle_handshake_record(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    record: &QlHandshakeRecord,
) -> Result<(), ReceiveError> {
    match record {
        QlHandshakeRecord::Ik1(message) => ik::handle_ik1(fsm, crypto, message),
        QlHandshakeRecord::Ik2(message) => ik::handle_ik2(fsm, crypto, message),
        QlHandshakeRecord::Kk1(message) => kk::handle_kk1(fsm, crypto, message),
        QlHandshakeRecord::Kk2(message) => kk::handle_kk2(fsm, crypto, message),
        QlHandshakeRecord::Xx1(message) => xx::handle_xx1(fsm, crypto, message),
        QlHandshakeRecord::Xx2(message) => xx::handle_xx2(fsm, crypto, message),
        QlHandshakeRecord::Xx3(message) => xx::handle_xx3(fsm, crypto, message),
        QlHandshakeRecord::Xx4(message) => xx::handle_xx4(fsm, crypto, message),
    }
}

pub fn handle_timer(fsm: &mut QlFsm) {
    let Some(deadline) = fsm.state.link.handshake_deadline() else {
        return;
    };
    if deadline > fsm.state.now {
        return;
    }

    fsm.state.link = LinkState::Idle;
    fsm.state.handshake = None;
    emit_peer_status(fsm, fsm.state.link.status());
}

pub fn next_handshake_deadline(fsm: &QlFsm) -> Option<std::time::Instant> {
    fsm.state.link.handshake_deadline()
}

pub fn finish_handshake(
    fsm: &mut QlFsm,
    handshake_id: HandshakeId,
    transport: SessionTransport,
    remote_bundle: wire::PeerBundle,
) -> Result<(), ReceiveError> {
    let qid = remote_bundle.qid;
    if let Some(peer) = fsm.state.peer.as_ref() {
        if peer != &remote_bundle {
            return Err(ReceiveError::InvalidRemoteBundle);
        }
    } else {
        fsm.state.peer = Some(remote_bundle);
        fsm.events.push_back(Event::NewPeer);
    }

    let config = &fsm.config;
    let session = SessionFsm::new(
        SessionConfig {
            local_parity: StreamParity::for_local(fsm.identity.qid, qid),
            record_max_size: config.session_record_max_size,
            ack_delay: config.session_record_ack_delay,
            retransmit_timeout: config.session_record_retransmit_timeout,
            keepalive_interval: config.session_keepalive_interval,
            peer_timeout: config.session_peer_timeout,
            stream_send_buffer_size: config.session_stream_send_buffer_size,
            stream_receive_buffer_size: config.session_stream_receive_buffer_size,
            accepted_record_window: config.session_accepted_record_window,
            pending_ack_range_limit: config.session_pending_ack_range_limit,
            initial_peer_stream_receive_window: transport
                .remote_transport_params
                .initial_stream_receive_window,
        },
        fsm.state.now,
    );
    fsm.state.link = LinkState::Connected(ConnectedState {
        handshake_id,
        transport,
        session,
    });
    emit_peer_status(fsm, fsm.state.link.status());
    Ok(())
}

pub fn establish_session(
    fsm: &mut QlFsm,
    handshake_id: HandshakeId,
    finalized: wire::FinalizedHandshake,
) -> Result<(), ReceiveError> {
    let transport = SessionTransport {
        tx_key: finalized.tx_key,
        rx_key: finalized.rx_key,
        tx_connection_id: finalized.tx_connection_id,
        rx_connection_id: finalized.rx_connection_id,
        remote_transport_params: finalized.remote_transport_params,
    };
    finish_handshake(fsm, handshake_id, transport, finalized.remote_bundle)
}

pub fn reset_connected_session_if_needed(fsm: &mut QlFsm) {
    if matches!(fsm.state.link, LinkState::Connected(_)) {
        fsm.state.link = LinkState::Idle;
    }
}

fn local_start_wins(local: &EphemeralPublicKey, inbound: &EphemeralPublicKey) -> bool {
    local.mlkem_public_key.as_bytes() <= inbound.mlkem_public_key.as_bytes()
}

fn is_connected_replay(
    fsm: &QlFsm,
    handshake_id: HandshakeId,
    sender: QID,
    recipient: QID,
) -> bool {
    let LinkState::Connected(connected) = &fsm.state.link else {
        return false;
    };

    connected.handshake_id == handshake_id
        && recipient == fsm.identity.qid
        && fsm.state.peer.as_ref().map(|peer| peer.qid) == Some(sender)
}
