mod ik;
mod xx;

use ql_common::QID;
use ql_wire::{
    self as wire, EphemeralPublicKey, HandshakeId, IkPattern, MlKemPublicKey, QlCrypto,
    QlHandshakeRecord, RouteHeader,
};

use crate::{
    fsm::emit_peer_status,
    session::{SessionFsm, SessionParams, StreamParity},
    state::{ConnectedState, LinkState, SessionTransport},
    Event, NoPeerError, QlFsm, ReceiveError, StreamMeta,
};

pub fn handle_connect_ik<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    crypto: &impl QlCrypto,
) -> Result<(), NoPeerError> {
    let peer = fsm.state.peer.clone().ok_or(NoPeerError)?;
    prepare_for_outbound_connect(fsm);
    ik::start_initiator(fsm, crypto, peer, IkPattern::Ik);
    Ok(())
}

pub fn handle_connect_kk<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    crypto: &impl QlCrypto,
) -> Result<(), NoPeerError> {
    let peer = fsm.state.peer.clone().ok_or(NoPeerError)?;
    prepare_for_outbound_connect(fsm);
    ik::start_initiator(fsm, crypto, peer, IkPattern::Kk);
    Ok(())
}

pub fn handle_connect_xx<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    invite: crate::PairingInvite,
    crypto: &impl QlCrypto,
) {
    prepare_for_outbound_connect(fsm);
    xx::start_initiator(fsm, crypto, invite.token, invite.qid);
}

pub fn next_handshake_id<M: StreamMeta>(fsm: &mut QlFsm<M>) -> HandshakeId {
    let handshake_id = wire::HandshakeId(fsm.state.next_control_id);
    fsm.state.next_control_id = fsm.state.next_control_id.wrapping_add(1);
    handshake_id
}

pub fn enqueue_handshake<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    route: RouteHeader,
    record: QlHandshakeRecord,
) {
    debug_assert!(fsm.state.handshake.is_none());
    fsm.state.handshake = Some((route, record));
}

pub fn handle_disarm_pairing<M: StreamMeta>(fsm: &mut QlFsm<M>) {
    xx::disarm_pairing(fsm);
}

fn local_transport_params<M: StreamMeta>(fsm: &QlFsm<M>) -> wire::TransportParams {
    wire::TransportParams {
        initial_stream_receive_window: fsm.config.session.stream_receive_buffer_size,
    }
}

pub fn prepare_for_outbound_connect<M: StreamMeta>(fsm: &mut QlFsm<M>) {
    fsm.state.handshake = None;
    reset_connected_session_if_needed(fsm);
}

pub fn handle_handshake_record<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    record: &QlHandshakeRecord,
) -> Result<(), ReceiveError> {
    match record {
        QlHandshakeRecord::Ik1(message) => ik::handle_1(fsm, crypto, route, message, IkPattern::Ik),
        QlHandshakeRecord::Ik2(message) => ik::handle_2(fsm, crypto, route, message, IkPattern::Ik),
        QlHandshakeRecord::Kk1(message) => ik::handle_1(fsm, crypto, route, message, IkPattern::Kk),
        QlHandshakeRecord::Kk2(message) => ik::handle_2(fsm, crypto, route, message, IkPattern::Kk),
        QlHandshakeRecord::Xx1(message) => xx::handle_xx1(fsm, crypto, route, message),
        QlHandshakeRecord::Xx2(message) => xx::handle_xx2(fsm, crypto, route, message),
        QlHandshakeRecord::Xx3(message) => xx::handle_xx3(fsm, crypto, route, message),
        QlHandshakeRecord::Xx4(message) => xx::handle_xx4(fsm, crypto, route, message),
    }
}

pub fn handle_timer<M: StreamMeta>(fsm: &mut QlFsm<M>) {
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

pub fn next_handshake_deadline<M: StreamMeta>(fsm: &QlFsm<M>) -> Option<std::time::Instant> {
    fsm.state.link.handshake_deadline()
}

pub fn finish_handshake<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
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

    let session = SessionFsm::new(
        fsm.config.session,
        SessionParams {
            local_parity: StreamParity::for_local(fsm.identity.qid, qid),
            initial_stream_receive_window: transport
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

pub fn establish_session<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    handshake_id: HandshakeId,
    finalized: wire::FinalizedHandshake,
) -> Result<(), ReceiveError> {
    let transport = SessionTransport {
        remote_qid: finalized.remote_bundle.qid,
        tx_key: finalized.tx_key,
        rx_key: finalized.rx_key,
        remote_transport_params: finalized.remote_transport_params,
    };
    finish_handshake(fsm, handshake_id, transport, finalized.remote_bundle)
}

pub fn reset_connected_session_if_needed<M: StreamMeta>(fsm: &mut QlFsm<M>) {
    if matches!(fsm.state.link, LinkState::Connected(_)) {
        fsm.state.link = LinkState::Idle;
    }
}

fn local_start_wins(local: &MlKemPublicKey, inbound: &EphemeralPublicKey) -> bool {
    local.as_bytes() <= inbound.mlkem_public_key.as_bytes()
}

fn is_connected_replay<M: StreamMeta>(
    fsm: &QlFsm<M>,
    handshake_id: HandshakeId,
    sender: QID,
) -> bool {
    let LinkState::Connected(connected) = &fsm.state.link else {
        return false;
    };

    connected.handshake_id == handshake_id
        && fsm.state.peer.as_ref().map(|peer| peer.qid) == Some(sender)
}
