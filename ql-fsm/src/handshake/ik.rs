use ql_wire::{self as wire, Ik1, Ik2, PeerBundle, QlCrypto, QlHandshakeRecord};

use super::{
    emit_peer_status, enqueue_handshake, finish_handshake, reset_connected_session_if_needed,
};
use crate::{
    state::{IkInitiatorState, LinkState, SessionTransport},
    QlFsm, ReceiveError,
};

pub fn start_initiator(fsm: &mut QlFsm, crypto: &impl QlCrypto, peer: PeerBundle) {
    let meta = super::next_handshake_meta(fsm);
    let mut handshake = wire::IkHandshake::new_initiator(
        crypto,
        fsm.identity.clone(),
        peer,
        super::local_transport_params(fsm),
    );
    let message = handshake.write_1(crypto, meta).unwrap();

    fsm.state.link = LinkState::IkInitiator(IkInitiatorState {
        handshake_id: meta.handshake_id,
        initial_ephemeral: message.ephemeral.clone(),
        handshake,
        deadline: fsm.state.now + fsm.config.handshake_timeout,
    });
    enqueue_handshake(fsm, QlHandshakeRecord::Ik1(message));
    emit_peer_status(fsm, fsm.state.link.status());
}

pub fn handle_ik1(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    message: &Ik1,
) -> Result<(), ReceiveError> {
    if should_ignore_inbound(fsm, message) {
        return Ok(());
    }
    if message.header.recipient != fsm.identity.xid {
        return Err(ReceiveError::InvalidXid);
    }
    if let Some(peer) = fsm.state.peer.as_ref() {
        if message.header.sender != peer.xid {
            return Err(ReceiveError::InvalidXid);
        }
    }

    reset_connected_session_if_needed(fsm);

    let mut handshake = wire::IkHandshake::new_responder(
        crypto,
        fsm.identity.clone(),
        fsm.state.peer.clone(),
        super::local_transport_params(fsm),
    );
    handshake.read_1(crypto, message)?;
    let outbound = handshake.write_2(crypto, message.meta)?;
    let (transport, remote_bundle) = SessionTransport::from_finalized(handshake.finalize(crypto)?);
    finish_handshake(fsm, transport, remote_bundle)?;
    fsm.state.handshake = None;
    enqueue_handshake(fsm, QlHandshakeRecord::Ik2(outbound));
    Ok(())
}

pub fn handle_ik2(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
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
            .read_2(crypto, message)?;
    }

    let LinkState::IkInitiator(state) = fsm.state.link.take() else {
        unreachable!("active IK initiator was checked above");
    };
    let (transport, remote_bundle) =
        SessionTransport::from_finalized(state.handshake.finalize(crypto)?);
    finish_handshake(fsm, transport, remote_bundle)
}

pub fn should_ignore_inbound(fsm: &QlFsm, message: &Ik1) -> bool {
    match &fsm.state.link {
        LinkState::Idle
        | LinkState::Connected(_)
        | LinkState::KkInitiator(_)
        | LinkState::XxInitiator(_)
        | LinkState::XxResponder(_) => false,
        LinkState::IkInitiator(state) => {
            if fsm.state.peer.as_ref().map(|peer| peer.xid) != Some(message.header.sender) {
                return false;
            }
            super::local_start_wins(&state.initial_ephemeral, &message.ephemeral)
        }
    }
}
