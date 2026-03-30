use ql_wire::{
    self as wire, HandshakeHeader, HandshakePayload, Kk1, Kk2, KkMessage, PeerBundle, QlCrypto,
    WireError, XID,
};

use super::{
    ensure_bound_peer, ensure_bound_peer_with_bundle, finish_handshake,
    reset_connected_session_if_needed, should_ignore_inbound_handshake_start,
};
use crate::{
    implementation::{emit_peer_status, enqueue_handshake, is_replayed_handshake_start},
    state::{ConnectionState, HandshakeMode, HandshakeState, SessionTransport},
    QlFsm, QlFsmError,
};

pub fn start_initiator(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    peer: XID,
    bundle: PeerBundle,
) -> Result<(), QlFsmError> {
    let header = HandshakeHeader {
        sender: fsm.identity.xid,
        recipient: peer,
    };
    let meta = super::next_handshake_meta(fsm);
    let mut handshake = wire::KkHandshake::new_initiator(crypto, fsm.identity.clone(), bundle);
    let message = handshake.write_message(crypto, header, meta)?;
    let payload = kk_payload(message);
    let initial_ephemeral = match &payload {
        HandshakePayload::Kk1(message) => Some(message.ephemeral.clone()),
        _ => None,
    };

    if let Some(entry) = fsm.peer.as_mut() {
        entry.session = ConnectionState::Handshaking(HandshakeState {
            id: meta.handshake_id,
            deadline: fsm.state.now.instant + fsm.config.handshake_timeout,
            mode: HandshakeMode::KkInitiator(handshake),
            initial_ephemeral,
        });
    }
    enqueue_handshake(fsm, peer, payload);
    emit_peer_status(fsm);
    Ok(())
}

pub fn handle_kk1(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    header: HandshakeHeader,
    message: &Kk1,
) -> Result<(), QlFsmError> {
    if should_ignore_inbound_handshake_start(fsm, header.sender, false, &message.ephemeral) {
        return Ok(());
    }

    if is_replayed_handshake_start(fsm, header.sender, message.meta) {
        return Ok(());
    }
    ensure_bound_peer_with_bundle(fsm, header.sender)?;
    reset_connected_session_if_needed(fsm);

    let bundle = fsm
        .peer
        .as_ref()
        .and_then(|entry| entry.peer.bundle.clone())
        .ok_or(QlFsmError::NoPeerBound)?;
    let mut handshake = wire::KkHandshake::new_responder(crypto, fsm.identity.clone(), bundle);
    handshake.read_message(
        crypto,
        header,
        fsm.state.now.unix_secs,
        &KkMessage::Message1(message.clone()),
    )?;
    let outbound = handshake.write_message(
        crypto,
        HandshakeHeader {
            sender: fsm.identity.xid,
            recipient: header.sender,
        },
        message.meta,
    )?;
    let (transport, remote_bundle) = SessionTransport::from_finalized(handshake.finalize(crypto)?);
    finish_handshake(fsm, transport, remote_bundle)?;
    fsm.state.handshake = None;
    enqueue_handshake(fsm, header.sender, kk_payload(outbound));
    Ok(())
}

pub fn handle_kk2(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    header: HandshakeHeader,
    message: &Kk2,
) -> Result<(), QlFsmError> {
    ensure_bound_peer(fsm, header.sender)?;
    let session = match fsm.peer.as_ref() {
        Some(entry) => entry.session.clone(),
        None => return Ok(()),
    };
    let ConnectionState::Handshaking(HandshakeState {
        mode: HandshakeMode::KkInitiator(mut handshake),
        ..
    }) = session
    else {
        return Ok(());
    };

    match handshake.read_message(
        crypto,
        header,
        fsm.state.now.unix_secs,
        &KkMessage::Message2(message.clone()),
    ) {
        Ok(()) => {}
        Err(WireError::InvalidState) => return Ok(()),
        Err(error) => return Err(error.into()),
    }

    let (transport, remote_bundle) = SessionTransport::from_finalized(handshake.finalize(crypto)?);
    finish_handshake(fsm, transport, remote_bundle)
}

fn kk_payload(message: KkMessage) -> HandshakePayload {
    match message {
        KkMessage::Message1(message) => HandshakePayload::Kk1(message),
        KkMessage::Message2(message) => HandshakePayload::Kk2(message),
    }
}
