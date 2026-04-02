use ql_wire::{self as wire, Ik1, Ik2, IkMessage, PeerBundle, QlCrypto, QlHandshakeRecord};

use super::{
    enqueue_handshake, finish_handshake, is_replayed_handshake_start,
    reset_connected_session_if_needed,
};
use crate::{
    implementation::emit_peer_status,
    state::{IkInitiatorState, LinkState, SessionTransport},
    QlFsm, QlFsmError,
};

pub fn start_initiator(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    peer: PeerBundle,
) -> Result<(), QlFsmError> {
    let meta = super::next_handshake_meta(fsm);
    let mut handshake = wire::IkHandshake::new_initiator(crypto, fsm.identity.clone(), peer);
    let message = handshake.write_message(crypto, meta)?;
    let IkMessage::Message1(message) = message else {
        return Err(QlFsmError::InvalidPayload);
    };

    fsm.state.link = LinkState::IkInitiator(IkInitiatorState {
        handshake_id: meta.handshake_id,
        initial_ephemeral: message.ephemeral.clone(),
        handshake,
        deadline: fsm.state.now.instant + fsm.config.handshake_timeout,
    });
    enqueue_handshake(fsm, QlHandshakeRecord::Ik1(message));
    emit_peer_status(fsm);
    Ok(())
}

pub fn handle_ik1(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    message: &Ik1,
) -> Result<(), QlFsmError> {
    if should_ignore_inbound(fsm, message) {
        return Ok(());
    }
    if is_replayed_handshake_start(fsm, message.meta) {
        return Ok(());
    }
    if message.header.recipient != fsm.identity.xid {
        return Err(QlFsmError::InvalidXid);
    }
    if let Some(peer) = fsm.state.peer.as_ref() {
        if message.header.sender != peer.xid {
            return Err(QlFsmError::InvalidXid);
        }
    }

    reset_connected_session_if_needed(fsm);

    let mut handshake =
        wire::IkHandshake::new_responder(crypto, fsm.identity.clone(), fsm.state.peer.clone());
    handshake.read_message(
        crypto,
        fsm.state.now.unix_secs,
        &IkMessage::Message1(message.clone()),
    )?;
    let outbound = handshake.write_message(crypto, message.meta)?;
    let (transport, remote_bundle) = SessionTransport::from_finalized(handshake.finalize(crypto)?);
    finish_handshake(fsm, transport, remote_bundle)?;
    fsm.state.handshake = None;
    enqueue_handshake(fsm, ik_record(outbound));
    Ok(())
}

pub fn handle_ik2(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    message: &Ik2,
) -> Result<(), QlFsmError> {
    {
        let LinkState::IkInitiator(state) = &mut fsm.state.link else {
            return Ok(());
        };

        if message.meta.handshake_id != state.handshake_id {
            return Ok(());
        }

        state.handshake.read_message(
            crypto,
            fsm.state.now.unix_secs,
            &IkMessage::Message2(message.clone()),
        )?;
    }

    let LinkState::IkInitiator(state) = fsm.state.link.take() else {
        unreachable!("active IK initiator was checked above");
    };
    let (transport, remote_bundle) =
        SessionTransport::from_finalized(state.handshake.finalize(crypto)?);
    finish_handshake(fsm, transport, remote_bundle)
}

fn ik_record(message: IkMessage) -> QlHandshakeRecord {
    match message {
        IkMessage::Message1(message) => QlHandshakeRecord::Ik1(message),
        IkMessage::Message2(message) => QlHandshakeRecord::Ik2(message),
    }
}

pub fn should_ignore_inbound(fsm: &QlFsm, message: &Ik1) -> bool {
    match &fsm.state.link {
        LinkState::Idle | LinkState::Connected(_) => false,
        LinkState::IkInitiator(state) => {
            if fsm.state.peer.as_ref().map(|peer| peer.xid) != Some(message.header.sender) {
                return false;
            }
            super::local_start_wins(&state.initial_ephemeral, &message.ephemeral)
        }
        LinkState::KkInitiator(_) => false,
    }
}
