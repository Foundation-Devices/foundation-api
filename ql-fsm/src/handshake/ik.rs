use ql_wire::{
    self as wire, Ik1, Ik2, IkPattern, PeerBundle, QlCrypto, QlHandshakeRecord, RouteHeader,
};

use super::{
    emit_peer_status, enqueue_handshake, establish_session, reset_connected_session_if_needed,
};
use crate::{
    state::{InitiatorState, LinkState},
    QlFsm, ReceiveError, ReceiveStage, StreamMeta,
};

pub fn start_initiator<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    crypto: &impl QlCrypto,
    peer: PeerBundle,
    pattern: IkPattern,
) {
    let handshake_id = super::next_handshake_id(fsm);
    let route = RouteHeader {
        sender: fsm.identity.qid,
        recipient: peer.qid,
    };
    let mut handshake = match pattern {
        IkPattern::Ik => wire::IkHandshake::new_ik_initiator(
            crypto,
            fsm.identity.clone(),
            peer,
            super::local_transport_params(fsm),
        ),
        IkPattern::Kk => wire::IkHandshake::new_kk_initiator(
            crypto,
            fsm.identity.clone(),
            peer,
            super::local_transport_params(fsm),
        ),
    };
    let message = handshake.write_1(crypto, handshake_id).unwrap();
    let state = InitiatorState {
        handshake,
        deadline: fsm.state.now + fsm.config.handshake_timeout,
    };

    fsm.state.link = LinkState::IkInitiator(state);
    let record = match pattern {
        IkPattern::Ik => QlHandshakeRecord::Ik1(message),
        IkPattern::Kk => QlHandshakeRecord::Kk1(message),
    };
    enqueue_handshake(fsm, route, record);
    emit_peer_status(fsm, fsm.state.link.status());
}

pub fn handle_1<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    message: &Ik1,
    pattern: IkPattern,
) -> Result<(), ReceiveError> {
    if should_ignore_inbound(fsm, route, message, pattern) {
        return Ok(());
    }

    let peer = fsm.state.peer.clone();
    if pattern == IkPattern::Kk && peer.is_none() {
        return Err(ReceiveError::NoPeer);
    }
    if peer.as_ref().is_some_and(|peer| route.sender != peer.qid) {
        return Err(ReceiveError::InvalidQid);
    }

    reset_connected_session_if_needed(fsm);

    let mut handshake = match (pattern, peer) {
        (IkPattern::Ik, expected_remote) => wire::IkHandshake::new_ik_responder(
            crypto,
            &fsm.identity,
            expected_remote,
            super::local_transport_params(fsm),
        ),
        (IkPattern::Kk, Some(remote_bundle)) => wire::IkHandshake::new_kk_responder(
            crypto,
            &fsm.identity,
            remote_bundle,
            super::local_transport_params(fsm),
        ),
        (IkPattern::Kk, None) => unreachable!("KK peer was checked above"),
    };
    handshake
        .read_1(crypto, route, message)
        .map_err(|source| wire_error(pattern, source))?;
    let outbound = handshake
        .write_2(crypto, message.handshake_id)
        .map_err(|source| wire_error(pattern, source))?;
    establish_session(
        fsm,
        message.handshake_id,
        handshake
            .finalize(crypto)
            .map_err(|source| wire_error(pattern, source))?,
    )?;
    fsm.state.handshake = None;
    let record = match pattern {
        IkPattern::Ik => QlHandshakeRecord::Ik2(outbound),
        IkPattern::Kk => QlHandshakeRecord::Kk2(outbound),
    };
    enqueue_handshake(
        fsm,
        RouteHeader {
            sender: fsm.identity.qid,
            recipient: route.sender,
        },
        record,
    );
    Ok(())
}

pub fn handle_2<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    message: &Ik2,
    pattern: IkPattern,
) -> Result<(), ReceiveError> {
    let LinkState::IkInitiator(state) = &mut fsm.state.link else {
        return Ok(());
    };
    if state.handshake.pattern() != pattern
        || state.handshake.handshake_id() != Some(message.handshake_id)
    {
        return Ok(());
    }
    state
        .handshake
        .read_2(crypto, route, message)
        .map_err(|source| wire_error(pattern, source))?;

    let LinkState::IkInitiator(state) = fsm.state.link.take() else {
        unreachable!("active handshake initiator was checked above");
    };
    establish_session(
        fsm,
        message.handshake_id,
        state
            .handshake
            .finalize(crypto)
            .map_err(|source| wire_error(pattern, source))?,
    )
}

fn should_ignore_inbound<M: StreamMeta>(
    fsm: &QlFsm<M>,
    route: RouteHeader,
    message: &Ik1,
    pattern: IkPattern,
) -> bool {
    match &fsm.state.link {
        LinkState::Idle | LinkState::XxInitiator(_) | LinkState::XxResponder(_) => false,
        LinkState::Connected(_) => {
            super::is_connected_replay(fsm, message.handshake_id, route.sender)
        }
        LinkState::IkInitiator(state) => {
            if state.handshake.pattern() != pattern {
                return pattern == IkPattern::Kk;
            }
            if fsm.state.peer.as_ref().map(|peer| peer.qid) == Some(route.sender) {
                super::local_start_wins(
                    state
                        .handshake
                        .local_ephemeral()
                        .expect("initiator has sent message 1"),
                    &message.ephemeral,
                )
            } else {
                false
            }
        }
    }
}

fn wire_error(pattern: IkPattern, source: ql_wire::Error) -> ReceiveError {
    ReceiveError::wire(
        match pattern {
            IkPattern::Ik => ReceiveStage::IkHandshake,
            IkPattern::Kk => ReceiveStage::KkHandshake,
        },
        source,
    )
}
