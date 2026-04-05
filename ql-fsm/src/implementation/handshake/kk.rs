use ql_wire::{self as wire, Kk1, Kk2, PeerBundle, QlCrypto, QlHandshakeRecord};

use super::{
    emit_peer_status, enqueue_handshake, finish_handshake, is_replayed_handshake_start,
    reset_connected_session_if_needed,
};
use crate::{
    state::{KkInitiatorState, LinkState, SessionTransport},
    QlFsm, QlFsmError, QlFsmEvent,
};

pub fn start_initiator(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    peer: PeerBundle,
    emit: &mut impl FnMut(QlFsmEvent),
) -> Result<(), QlFsmError> {
    let meta = super::next_handshake_meta(fsm);
    let mut handshake = wire::KkHandshake::new_initiator(
        crypto,
        fsm.identity.clone(),
        peer,
        super::local_transport_params(fsm),
    );
    let message = handshake.write_1(crypto, meta)?;

    fsm.state.link = LinkState::KkInitiator(KkInitiatorState {
        handshake_id: meta.handshake_id,
        initial_ephemeral: message.ephemeral.clone(),
        handshake,
        deadline: fsm.state.now.instant + fsm.config.handshake_timeout,
    });
    enqueue_handshake(fsm, QlHandshakeRecord::Kk1(message));
    emit_peer_status(fsm, emit);
    Ok(())
}

pub fn handle_kk1(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    message: &Kk1,
    emit: &mut impl FnMut(QlFsmEvent),
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

    let mut handshake = wire::KkHandshake::new_responder(
        crypto,
        fsm.identity.clone(),
        peer,
        super::local_transport_params(fsm),
    );
    handshake.read_1(crypto, fsm.state.now.unix_secs, message)?;
    let outbound = handshake.write_2(crypto, message.meta)?;
    let (transport, remote_bundle) = SessionTransport::from_finalized(handshake.finalize(crypto)?);
    finish_handshake(fsm, transport, remote_bundle, emit)?;
    fsm.state.handshake = None;
    enqueue_handshake(fsm, QlHandshakeRecord::Kk2(outbound));
    Ok(())
}

pub fn handle_kk2(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    message: &Kk2,
    emit: &mut impl FnMut(QlFsmEvent),
) -> Result<(), QlFsmError> {
    {
        let LinkState::KkInitiator(state) = &mut fsm.state.link else {
            return Ok(());
        };

        if message.meta.handshake_id != state.handshake_id {
            return Ok(());
        }

        state
            .handshake
            .read_2(crypto, fsm.state.now.unix_secs, message)?;
    }

    let LinkState::KkInitiator(state) = fsm.state.link.take() else {
        unreachable!("active KK initiator was checked above");
    };
    let (transport, remote_bundle) =
        SessionTransport::from_finalized(state.handshake.finalize(crypto)?);
    finish_handshake(fsm, transport, remote_bundle, emit)
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
