use ql_wire::{
    self as wire, QlCrypto, QlHandshakeRecord, WireError, Xx1, Xx2, Xx3, Xx4, XxMessage,
};

use super::{
    enqueue_handshake, finish_handshake, is_replayed_handshake_start,
    reset_connected_session_if_needed,
};
use crate::{
    implementation::emit_peer_status,
    state::{LinkState, SessionTransport},
    QlFsm, QlFsmError,
};

pub fn start_initiator(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
    let meta = super::next_handshake_meta(fsm);
    let mut handshake = wire::XxHandshake::new_initiator(crypto, fsm.identity.clone());
    let message = handshake.write_message(crypto, meta)?;
    let XxMessage::Message1(message) = message else {
        return Err(QlFsmError::InvalidPayload);
    };

    fsm.state.link = LinkState::XxInitiator {
        initial_ephemeral: message.ephemeral.clone(),
        handshake,
        deadline: fsm.state.now.instant + fsm.config.handshake_timeout,
    };
    enqueue_handshake(fsm, QlHandshakeRecord::Xx1(message));
    emit_peer_status(fsm);
    Ok(())
}

pub fn handle_xx1(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    message: &Xx1,
) -> Result<(), QlFsmError> {
    if should_ignore_inbound(fsm, message) {
        return Ok(());
    }
    if is_replayed_handshake_start(fsm, message.meta) {
        return Ok(());
    }

    reset_connected_session_if_needed(fsm);

    let mut handshake = wire::XxHandshake::new_responder(crypto, fsm.identity.clone());
    handshake.read_message(
        crypto,
        fsm.state.now.unix_secs,
        &XxMessage::Message1(message.clone()),
    )?;
    let outbound = handshake.write_message(crypto, message.meta)?;

    fsm.state.handshake = None;
    fsm.state.link = LinkState::XxResponder {
        handshake,
        deadline: fsm.state.now.instant + fsm.config.handshake_timeout,
    };
    enqueue_handshake(fsm, xx_record(outbound));
    emit_peer_status(fsm);
    Ok(())
}

pub fn handle_xx2(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    message: &Xx2,
) -> Result<(), QlFsmError> {
    let LinkState::XxInitiator {
        mut handshake,
        deadline,
        initial_ephemeral,
    } = fsm.state.link.clone()
    else {
        return Ok(());
    };

    match handshake.read_message(
        crypto,
        fsm.state.now.unix_secs,
        &XxMessage::Message2(message.clone()),
    ) {
        Ok(()) => {}
        Err(WireError::InvalidState) => return Ok(()),
        Err(error) => return Err(error.into()),
    }

    let outbound = handshake.write_message(crypto, message.meta)?;
    fsm.state.handshake = None;
    fsm.state.link = LinkState::XxInitiator {
        handshake,
        deadline,
        initial_ephemeral,
    };
    enqueue_handshake(fsm, xx_record(outbound));
    Ok(())
}

pub fn handle_xx3(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    message: &Xx3,
) -> Result<(), QlFsmError> {
    let LinkState::XxResponder {
        mut handshake,
        deadline: _,
    } = fsm.state.link.clone()
    else {
        return Ok(());
    };

    match handshake.read_message(
        crypto,
        fsm.state.now.unix_secs,
        &XxMessage::Message3(message.clone()),
    ) {
        Ok(()) => {}
        Err(WireError::InvalidState) => return Ok(()),
        Err(error) => return Err(error.into()),
    }

    let outbound = handshake.write_message(crypto, message.meta)?;
    let (transport, remote_bundle) = SessionTransport::from_finalized(handshake.finalize(crypto)?);
    finish_handshake(fsm, transport, remote_bundle)?;
    fsm.state.handshake = None;
    enqueue_handshake(fsm, xx_record(outbound));
    Ok(())
}

pub fn handle_xx4(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    message: &Xx4,
) -> Result<(), QlFsmError> {
    let LinkState::XxInitiator {
        mut handshake,
        deadline: _,
        initial_ephemeral: _,
    } = fsm.state.link.clone()
    else {
        return Ok(());
    };

    match handshake.read_message(
        crypto,
        fsm.state.now.unix_secs,
        &XxMessage::Message4(message.clone()),
    ) {
        Ok(()) => {}
        Err(WireError::InvalidState) => return Ok(()),
        Err(error) => return Err(error.into()),
    }

    let (transport, remote_bundle) = SessionTransport::from_finalized(handshake.finalize(crypto)?);
    finish_handshake(fsm, transport, remote_bundle)
}

fn xx_record(message: XxMessage) -> QlHandshakeRecord {
    match message {
        XxMessage::Message1(message) => QlHandshakeRecord::Xx1(message),
        XxMessage::Message2(message) => QlHandshakeRecord::Xx2(message),
        XxMessage::Message3(message) => QlHandshakeRecord::Xx3(message),
        XxMessage::Message4(message) => QlHandshakeRecord::Xx4(message),
    }
}

pub fn should_ignore_inbound(fsm: &QlFsm, message: &Xx1) -> bool {
    match &fsm.state.link {
        LinkState::Idle | LinkState::Connected(_) => false,
        LinkState::XxResponder { .. } => true,
        LinkState::KkInitiator { .. } => false,
        LinkState::XxInitiator {
            initial_ephemeral, ..
        } => super::local_start_wins(initial_ephemeral, &message.ephemeral),
    }
}
