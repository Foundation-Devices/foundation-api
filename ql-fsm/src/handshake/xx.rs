use ql_common::QID;
use ql_wire::{
    self as wire, PairingToken, QlCrypto, QlHandshakeRecord, RouteHeader, Xx1, Xx2, Xx3, Xx4,
};

use super::{
    emit_peer_status, enqueue_handshake, establish_session, reset_connected_session_if_needed,
};
use crate::{
    state::{InitiatorState, LinkState, XxResponderState},
    QlFsm, ReceiveError,
};

pub fn start_initiator(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    token: PairingToken,
    remote_qid: QID,
) {
    let meta = super::next_handshake_meta(fsm);
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
    let message = handshake.write_1(crypto, meta).unwrap();

    fsm.state.link = LinkState::XxInitiator(InitiatorState {
        handshake_id: meta.handshake_id,
        initial_ephemeral: message.ephemeral.clone(),
        handshake,
        deadline: fsm.state.now + fsm.config.handshake_timeout,
    });
    enqueue_handshake(fsm, route, QlHandshakeRecord::Xx1(message));
    emit_peer_status(fsm, fsm.state.link.status());
}

pub fn handle_xx1(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    message: &Xx1,
) -> Result<(), ReceiveError> {
    if should_ignore_inbound(fsm, crypto, route, message) {
        return Ok(());
    }
    match fsm.state.armed_pairing_token {
        Some(expected) if expected.id(crypto) != message.pairing_id => {
            Err(ReceiveError::InvalidPairingId {
                expected: expected.id(crypto),
                actual: message.pairing_id,
            })
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
                .map_err(ReceiveError::InvalidXxHandshake)?;
            let outbound = handshake
                .write_2(crypto, message.meta)
                .map_err(ReceiveError::InvalidXxHandshake)?;
            fsm.state.link = LinkState::XxResponder(XxResponderState {
                handshake,
                handshake_meta: message.meta,
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

pub fn handle_xx2(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    message: &Xx2,
) -> Result<(), ReceiveError> {
    {
        let LinkState::XxInitiator(state) = &mut fsm.state.link else {
            return Ok(());
        };

        if message.meta.handshake_id != state.handshake_id {
            return Ok(());
        }

        state
            .handshake
            .read_2(crypto, route, message)
            .map_err(ReceiveError::InvalidXxHandshake)?;
        let outbound = state
            .handshake
            .write_3(crypto, message.meta)
            .map_err(ReceiveError::InvalidXxHandshake)?;
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

pub fn handle_xx3(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    message: &Xx3,
) -> Result<(), ReceiveError> {
    let LinkState::XxResponder(state) = &mut fsm.state.link else {
        return Ok(());
    };

    if message.meta.handshake_id != state.handshake_meta.handshake_id {
        return Ok(());
    }

    state
        .handshake
        .read_3(crypto, route, message)
        .map_err(ReceiveError::InvalidXxHandshake)?;
    let handshake_meta = state.handshake_meta;
    let LinkState::XxResponder(mut state) = fsm.state.link.take() else {
        unreachable!("active XX responder was checked above");
    };
    let outbound = state
        .handshake
        .write_4(crypto, handshake_meta)
        .map_err(ReceiveError::InvalidXxHandshake)?;
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
        message.meta.handshake_id,
        state
            .handshake
            .finalize(crypto)
            .map_err(ReceiveError::InvalidXxHandshake)?,
    )
}

pub fn handle_xx4(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    message: &Xx4,
) -> Result<(), ReceiveError> {
    {
        let LinkState::XxInitiator(state) = &mut fsm.state.link else {
            return Ok(());
        };

        if message.meta.handshake_id != state.handshake_id {
            return Ok(());
        }

        state
            .handshake
            .read_4(crypto, route, message)
            .map_err(ReceiveError::InvalidXxHandshake)?;
    }

    let LinkState::XxInitiator(state) = fsm.state.link.take() else {
        unreachable!("active XX initiator was checked above");
    };
    establish_session(
        fsm,
        message.meta.handshake_id,
        state
            .handshake
            .finalize(crypto)
            .map_err(ReceiveError::InvalidXxHandshake)?,
    )
}

pub fn disarm_pairing(fsm: &mut QlFsm) {
    if matches!(fsm.state.link, LinkState::XxResponder(_)) {
        fsm.state.link = LinkState::Idle;
        fsm.state.handshake = None;
    }
}

pub fn should_ignore_inbound(
    fsm: &QlFsm,
    crypto: &impl QlCrypto,
    route: RouteHeader,
    message: &Xx1,
) -> bool {
    match &fsm.state.link {
        LinkState::Idle => false,
        LinkState::Connected(_) => {
            super::is_connected_replay(fsm, message.meta.handshake_id, route.sender)
        }
        LinkState::IkInitiator(_) | LinkState::KkInitiator(_) | LinkState::XxResponder(_) => true,
        LinkState::XxInitiator(state) => {
            if state.handshake.pairing_id(crypto) != message.pairing_id {
                return false;
            }
            if route.sender != state.handshake.remote_qid() {
                return false;
            }
            super::local_start_wins(&state.initial_ephemeral, &message.ephemeral)
        }
    }
}
