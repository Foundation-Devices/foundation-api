use ql_common::QID;
use ql_wire::{
    self as wire, PairingToken, QlCrypto, QlHandshakeRecord, RouteHeader, Xx1, Xx2, Xx3, Xx4,
};

use super::{
    emit_peer_status, enqueue_handshake, establish_session, reset_connected_session_if_needed,
};
use crate::{
    state::{InitiatorState, LinkState, XxResponderState},
    QlFsm, ReceiveError, ReceiveStage, StreamMeta,
};

pub fn start_initiator<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    crypto: &impl QlCrypto,
    token: PairingToken,
    remote_qid: QID,
) {
    let handshake_id = super::next_handshake_id(fsm);
    let route = RouteHeader {
        sender: fsm.identity.qid,
        recipient: remote_qid,
    };
    let mut handshake = wire::XxHandshake::new_initiator(
        crypto,
        fsm.identity.clone(),
        remote_qid,
        token,
        super::local_transport_params(fsm),
    );
    let message = handshake.write_1(crypto, handshake_id).unwrap();

    fsm.state.link = LinkState::XxInitiator(InitiatorState {
        handshake,
        deadline: fsm.state.now + fsm.config.handshake_timeout,
    });
    enqueue_handshake(fsm, route, QlHandshakeRecord::Xx1(message));
    emit_peer_status(fsm, fsm.state.link.status());
}

pub fn handle_xx1<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    message: &Xx1,
) -> Result<(), ReceiveError> {
    if should_ignore_inbound(fsm, crypto, route, message) {
        return Ok(());
    }
    match fsm.state.armed_pairing_token {
        Some(expected) if expected.id(crypto) != message.pairing_id => {
            Err(ReceiveError::InvalidPairingId)
        }
        Some(token) => {
            reset_connected_session_if_needed(fsm);

            let mut handshake = wire::XxHandshake::new_responder(
                crypto,
                fsm.identity.clone(),
                route.sender,
                token,
                super::local_transport_params(fsm),
            );
            handshake
                .read_1(crypto, route, message)
                .map_err(wire_error)?;
            let outbound = handshake
                .write_2(crypto, message.handshake_id)
                .map_err(wire_error)?;
            fsm.state.link = LinkState::XxResponder(XxResponderState {
                handshake,
                deadline: fsm.state.now + fsm.config.handshake_timeout,
            });
            fsm.state.handshake = None;
            enqueue_handshake(
                fsm,
                RouteHeader {
                    sender: fsm.identity.qid,
                    recipient: route.sender,
                },
                QlHandshakeRecord::Xx2(outbound),
            );
            Ok(())
        }
        None => Err(ReceiveError::NotPairingMode),
    }
}

pub fn handle_xx2<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    message: &Xx2,
) -> Result<(), ReceiveError> {
    {
        let LinkState::XxInitiator(state) = &mut fsm.state.link else {
            return Ok(());
        };

        if state.handshake.handshake_id() != Some(message.handshake_id) {
            return Ok(());
        }

        state
            .handshake
            .read_2(crypto, route, message)
            .map_err(wire_error)?;
        let outbound = state
            .handshake
            .write_3(crypto, message.handshake_id)
            .map_err(wire_error)?;
        fsm.state.handshake = None;
        enqueue_handshake(
            fsm,
            RouteHeader {
                sender: fsm.identity.qid,
                recipient: route.sender,
            },
            QlHandshakeRecord::Xx3(outbound),
        );
    }

    Ok(())
}

pub fn handle_xx3<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    message: &Xx3,
) -> Result<(), ReceiveError> {
    let LinkState::XxResponder(state) = &mut fsm.state.link else {
        return Ok(());
    };

    if state.handshake.handshake_id() != Some(message.handshake_id) {
        return Ok(());
    }

    state
        .handshake
        .read_3(crypto, route, message)
        .map_err(wire_error)?;
    let LinkState::XxResponder(mut state) = fsm.state.link.take() else {
        unreachable!("active XX responder was checked above");
    };
    let outbound = state
        .handshake
        .write_4(crypto, message.handshake_id)
        .map_err(wire_error)?;
    fsm.state.handshake = None;
    enqueue_handshake(
        fsm,
        RouteHeader {
            sender: fsm.identity.qid,
            recipient: route.sender,
        },
        QlHandshakeRecord::Xx4(outbound),
    );
    establish_session(
        fsm,
        message.handshake_id,
        state.handshake.finalize(crypto).map_err(wire_error)?,
    )
}

pub fn handle_xx4<M: StreamMeta>(
    fsm: &mut QlFsm<M>,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    message: &Xx4,
) -> Result<(), ReceiveError> {
    {
        let LinkState::XxInitiator(state) = &mut fsm.state.link else {
            return Ok(());
        };

        if state.handshake.handshake_id() != Some(message.handshake_id) {
            return Ok(());
        }

        state
            .handshake
            .read_4(crypto, route, message)
            .map_err(wire_error)?;
    }

    let LinkState::XxInitiator(state) = fsm.state.link.take() else {
        unreachable!("active XX initiator was checked above");
    };
    establish_session(
        fsm,
        message.handshake_id,
        state.handshake.finalize(crypto).map_err(wire_error)?,
    )
}

pub fn disarm_pairing<M: StreamMeta>(fsm: &mut QlFsm<M>) {
    if matches!(fsm.state.link, LinkState::XxResponder(_)) {
        fsm.state.link = LinkState::Idle;
        fsm.state.handshake = None;
    }
}

pub fn should_ignore_inbound<M: StreamMeta>(
    fsm: &QlFsm<M>,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    message: &Xx1,
) -> bool {
    match &fsm.state.link {
        LinkState::Idle => false,
        LinkState::Connected(_) => {
            super::is_connected_replay(fsm, message.handshake_id, route.sender)
        }
        LinkState::IkInitiator(_) | LinkState::XxResponder(_) => true,
        LinkState::XxInitiator(state) => {
            if state.handshake.pairing_id(crypto) != message.pairing_id {
                return false;
            }
            if route.sender != state.handshake.remote_qid() {
                return false;
            }
            super::local_start_wins(
                state
                    .handshake
                    .local_ephemeral()
                    .expect("initiator has sent message 1"),
                &message.ephemeral,
            )
        }
    }
}

fn wire_error(source: ql_wire::Error) -> ReceiveError {
    ReceiveError::wire(ReceiveStage::XxHandshake, source)
}
