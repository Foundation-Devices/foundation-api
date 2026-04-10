use ql_wire::{self as wire, PairingToken, QlCrypto, QlHandshakeRecord, Xx1, Xx2, Xx3, Xx4};

use super::{
    emit_peer_status, enqueue_handshake, finish_handshake, is_replayed_handshake_start,
    reset_connected_session_if_needed,
};
use crate::{
    state::{LinkState, SessionTransport, XxInitiatorState, XxResponderState},
    QlFsm, ReceiveError,
};

pub fn start_initiator(fsm: &mut QlFsm, crypto: &impl QlCrypto, token: PairingToken) {
    let meta = super::next_handshake_meta(fsm);
    let mut handshake = wire::XxHandshake::new_initiator(
        crypto,
        fsm.identity.clone(),
        token,
        super::local_transport_params(fsm),
    );
    let message = handshake.write_1(crypto, meta).unwrap();

    fsm.state.link = LinkState::XxInitiator(XxInitiatorState {
        handshake_id: meta.handshake_id,
        initial_ephemeral: message.ephemeral.clone(),
        handshake,
        deadline: fsm.state.now.instant + fsm.config.handshake_timeout,
    });
    enqueue_handshake(fsm, QlHandshakeRecord::Xx1(message));
    emit_peer_status(fsm);
}

pub fn handle_xx1(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    message: &Xx1,
) -> Result<(), ReceiveError> {
    if should_ignore_inbound(fsm, message) {
        return Ok(());
    }
    if is_replayed_handshake_start(fsm, message.meta) {
        return Err(ReceiveError::Replay);
    }
    if fsm.state.armed_pairing_token != Some(message.header.pairing_token) {
        return Err(ReceiveError::InvalidPairingToken);
    }

    reset_connected_session_if_needed(fsm);

    let mut handshake = wire::XxHandshake::new_responder(
        crypto,
        fsm.identity.clone(),
        message.header.pairing_token,
        super::local_transport_params(fsm),
    );
    handshake.read_1(crypto, fsm.state.now.unix_secs, message)?;
    let outbound = handshake.write_2(crypto, message.meta)?;
    fsm.state.link = LinkState::XxResponder(XxResponderState {
        handshake,
        handshake_meta: message.meta,
        deadline: fsm.state.now.instant + fsm.config.handshake_timeout,
    });
    fsm.state.handshake = None;
    enqueue_handshake(fsm, QlHandshakeRecord::Xx2(outbound));
    Ok(())
}

pub fn handle_xx2(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
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
            .read_2(crypto, fsm.state.now.unix_secs, message)?;
        let outbound = state.handshake.write_3(crypto, message.meta)?;
        fsm.state.handshake = None;
        enqueue_handshake(fsm, QlHandshakeRecord::Xx3(outbound));
    }

    Ok(())
}

pub fn handle_xx3(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
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
        .read_3(crypto, fsm.state.now.unix_secs, message)?;
    let handshake_meta = state.handshake_meta;
    let LinkState::XxResponder(mut state) = fsm.state.link.take() else {
        unreachable!("active XX responder was checked above");
    };
    let outbound = state.handshake.write_4(crypto, handshake_meta)?;
    fsm.state.handshake = None;
    enqueue_handshake(fsm, QlHandshakeRecord::Xx4(outbound));
    let (transport, remote_bundle) =
        SessionTransport::from_finalized(state.handshake.finalize(crypto)?);
    finish_handshake(fsm, transport, remote_bundle)
}

pub fn handle_xx4(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
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
            .read_4(crypto, fsm.state.now.unix_secs, message)?;
    }

    let LinkState::XxInitiator(state) = fsm.state.link.take() else {
        unreachable!("active XX initiator was checked above");
    };
    let (transport, remote_bundle) =
        SessionTransport::from_finalized(state.handshake.finalize(crypto)?);
    finish_handshake(fsm, transport, remote_bundle)
}

pub fn disarm_pairing(fsm: &mut QlFsm) {
    if matches!(fsm.state.link, LinkState::XxResponder(_)) {
        fsm.state.link = LinkState::Idle;
        fsm.state.handshake = None;
    }
}

pub fn should_ignore_inbound(fsm: &QlFsm, message: &Xx1) -> bool {
    match &fsm.state.link {
        LinkState::Idle | LinkState::Connected(_) => false,
        LinkState::IkInitiator(_) | LinkState::KkInitiator(_) | LinkState::XxResponder(_) => true,
        LinkState::XxInitiator(state) => {
            if state.handshake.pairing_token() != message.header.pairing_token {
                return false;
            }
            super::local_start_wins(&state.initial_ephemeral, &message.ephemeral)
        }
    }
}
