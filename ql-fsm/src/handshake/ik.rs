use ql_wire::{self as wire, Ik1, Ik2, PeerBundle, QlCrypto, QlHandshakeRecord, RouteHeader};

use super::{
    emit_peer_status, enqueue_handshake, establish_session, reset_connected_session_if_needed,
};
use crate::{
    state::{InitiatorState, LinkState},
    QlFsm, ReceiveError, ReceiveStage,
};

pub fn start_initiator(fsm: &mut QlFsm, crypto: &impl QlCrypto, peer: PeerBundle) {
    let meta = super::next_handshake_meta(fsm);
    let route = RouteHeader {
        sender: fsm.identity.qid,
        recipient: peer.qid,
    };
    let mut handshake = wire::IkHandshake::new_initiator(
        crypto,
        fsm.identity.clone(),
        peer,
        super::local_transport_params(fsm),
    );
    let message = handshake.write_1(crypto, meta).unwrap();

    fsm.state.link = LinkState::IkInitiator(InitiatorState {
        handshake_id: meta.handshake_id,
        initial_ephemeral: message.ephemeral.clone(),
        handshake,
        deadline: fsm.state.now + fsm.config.handshake_timeout,
    });
    enqueue_handshake(fsm, route, QlHandshakeRecord::Ik1(message));
    emit_peer_status(fsm, fsm.state.link.status());
}

pub fn handle_ik1(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    message: &Ik1,
) -> Result<(), ReceiveError> {
    if should_ignore_inbound(fsm, route, message) {
        return Ok(());
    }
    if let Some(peer) = fsm.state.peer.as_ref() {
        if route.sender != peer.qid {
            return Err(ReceiveError::InvalidQid);
        }
    }

    reset_connected_session_if_needed(fsm);

    let mut handshake = wire::IkHandshake::new_responder(
        crypto,
        fsm.identity.clone(),
        fsm.state.peer.clone(),
        super::local_transport_params(fsm),
    );
    handshake
        .read_1(crypto, route, message)
        .map_err(wire_error)?;
    let outbound = handshake
        .write_2(crypto, message.meta)
        .map_err(wire_error)?;
    establish_session(
        fsm,
        message.meta.handshake_id,
        handshake.finalize(crypto).map_err(wire_error)?,
    )?;
    fsm.state.handshake = None;
    enqueue_handshake(
        fsm,
        RouteHeader {
            sender: fsm.identity.qid,
            recipient: route.sender,
        },
        QlHandshakeRecord::Ik2(outbound),
    );
    Ok(())
}

pub fn handle_ik2(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    message: &Ik2,
) -> Result<(), ReceiveError> {
    {
        let LinkState::IkInitiator(state) = &mut fsm.state.link else {
            return Ok(());
        };

        if message.meta.handshake_id != state.handshake_id {
            return Ok(());
        }

        state
            .handshake
            .read_2(crypto, route, message)
            .map_err(wire_error)?;
    }

    let LinkState::IkInitiator(state) = fsm.state.link.take() else {
        unreachable!("active IK initiator was checked above");
    };
    establish_session(
        fsm,
        message.meta.handshake_id,
        state.handshake.finalize(crypto).map_err(wire_error)?,
    )
}

pub fn should_ignore_inbound(fsm: &QlFsm, route: RouteHeader, message: &Ik1) -> bool {
    match &fsm.state.link {
        LinkState::Idle
        | LinkState::KkInitiator(_)
        | LinkState::XxInitiator(_)
        | LinkState::XxResponder(_) => false,
        LinkState::Connected(_) => {
            super::is_connected_replay(fsm, message.meta.handshake_id, route.sender)
        }
        LinkState::IkInitiator(state) => {
            if fsm.state.peer.as_ref().map(|peer| peer.qid) != Some(route.sender) {
                return false;
            }
            super::local_start_wins(&state.initial_ephemeral, &message.ephemeral)
        }
    }
}

fn wire_error(source: ql_wire::Error) -> ReceiveError {
    ReceiveError::wire(ReceiveStage::IkHandshake, source)
}
