use ql_wire::{self as wire, Kk1, Kk2, KkMessage, PeerBundle, QlCrypto, QlHandshakeRecord};

use super::{
    enqueue_handshake, finish_handshake, is_replayed_handshake_start,
    reset_connected_session_if_needed,
};
use crate::{
    implementation::emit_peer_status,
    state::{KkInitiatorState, LinkState, SessionTransport},
    QlFsm, QlFsmError,
};

pub fn start_initiator(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    peer: PeerBundle,
) -> Result<(), QlFsmError> {
    let meta = super::next_handshake_meta(fsm);
    let mut handshake = wire::KkHandshake::new_initiator(crypto, fsm.identity.clone(), peer);
    let message = handshake.write_message(crypto, meta)?;
    let KkMessage::Message1(message) = message else {
        return Err(QlFsmError::InvalidPayload);
    };

    fsm.state.link = LinkState::KkInitiator(KkInitiatorState {
        handshake_id: meta.handshake_id,
        initial_ephemeral: message.ephemeral.clone(),
        handshake,
        deadline: fsm.state.now.instant + fsm.config.handshake_timeout,
    });
    enqueue_handshake(fsm, QlHandshakeRecord::Kk1(message));
    emit_peer_status(fsm);
    Ok(())
}

pub fn handle_kk1(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    message: &Kk1,
) -> Result<(), QlFsmError> {
    if should_ignore_inbound(fsm, message) {
        return Ok(());
    }
    if is_replayed_handshake_start(fsm, message.meta) {
        return Ok(());
    }

    let Some(peer) = fsm.state.peer.clone() else {
        return Err(QlFsmError::InvalidPayload);
    };
    if message.header.recipient != fsm.identity.xid || message.header.sender != peer.xid {
        return Err(QlFsmError::InvalidXid);
    }

    reset_connected_session_if_needed(fsm);

    let mut handshake = wire::KkHandshake::new_responder(crypto, fsm.identity.clone(), peer);
    handshake.read_message(
        crypto,
        fsm.state.now.unix_secs,
        &KkMessage::Message1(message.clone()),
    )?;
    let outbound = handshake.write_message(crypto, message.meta)?;
    let (transport, remote_bundle) = SessionTransport::from_finalized(handshake.finalize(crypto)?);
    finish_handshake(fsm, transport, remote_bundle)?;
    fsm.state.handshake = None;
    enqueue_handshake(fsm, kk_record(outbound));
    Ok(())
}

pub fn handle_kk2(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    message: &Kk2,
) -> Result<(), QlFsmError> {
    {
        let LinkState::KkInitiator(state) = &mut fsm.state.link else {
            return Ok(());
        };

        if message.meta.handshake_id != state.handshake_id {
            return Ok(());
        }

        state.handshake.read_message(
            crypto,
            fsm.state.now.unix_secs,
            &KkMessage::Message2(message.clone()),
        )?;
    }

    let LinkState::KkInitiator(state) = fsm.state.link.take() else {
        unreachable!("active KK initiator was checked above");
    };
    let (transport, remote_bundle) =
        SessionTransport::from_finalized(state.handshake.finalize(crypto)?);
    finish_handshake(fsm, transport, remote_bundle)
}

fn kk_record(message: KkMessage) -> QlHandshakeRecord {
    match message {
        KkMessage::Message1(message) => QlHandshakeRecord::Kk1(message),
        KkMessage::Message2(message) => QlHandshakeRecord::Kk2(message),
    }
}

pub fn should_ignore_inbound(fsm: &QlFsm, message: &Kk1) -> bool {
    match &fsm.state.link {
        LinkState::Idle | LinkState::Connected(_) => false,
        LinkState::IkInitiator(_) => true,
        LinkState::KkInitiator(state) => {
            if fsm.state.peer.as_ref().map(|peer| peer.xid) != Some(message.header.sender) {
                return false;
            }
            super::local_start_wins(&state.initial_ephemeral, &message.ephemeral)
        }
    }
}
