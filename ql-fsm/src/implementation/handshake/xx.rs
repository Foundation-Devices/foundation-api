use ql_wire::{
    self as wire, HandshakeHeader, HandshakePayload, QlCrypto, WireError, Xx1, Xx2, Xx3, Xx4,
    XxMessage, XID,
};

use super::{
    ensure_bound_peer, ensure_or_bind_peer, finish_handshake, reset_connected_session_if_needed,
    should_ignore_inbound_handshake_start,
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
) -> Result<(), QlFsmError> {
    let header = HandshakeHeader {
        sender: fsm.identity.xid,
        recipient: peer,
    };
    let meta = super::next_handshake_meta(fsm);
    let mut handshake = wire::XxHandshake::new_initiator(crypto, fsm.identity.clone());
    let message = handshake.write_message(crypto, header, meta)?;
    let payload = xx_payload(message);
    let initial_ephemeral = match &payload {
        HandshakePayload::Xx1(message) => Some(message.ephemeral.clone()),
        _ => None,
    };

    if let Some(entry) = fsm.peer.as_mut() {
        entry.session = ConnectionState::Handshaking(HandshakeState {
            id: meta.handshake_id,
            deadline: fsm.state.now.instant + fsm.config.handshake_timeout,
            mode: HandshakeMode::XxInitiator(handshake),
            initial_ephemeral,
        });
    }
    enqueue_handshake(fsm, peer, payload);
    emit_peer_status(fsm);
    Ok(())
}

pub fn handle_xx1(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    header: HandshakeHeader,
    message: &Xx1,
) -> Result<(), QlFsmError> {
    if should_ignore_inbound_handshake_start(fsm, header.sender, true, &message.ephemeral) {
        return Ok(());
    }

    if is_replayed_handshake_start(fsm, header.sender, message.meta) {
        return Ok(());
    }
    ensure_or_bind_peer(fsm, header.sender, None)?;
    reset_connected_session_if_needed(fsm);

    let mut handshake = wire::XxHandshake::new_responder(crypto, fsm.identity.clone());
    handshake.read_message(
        crypto,
        header,
        fsm.state.now.unix_secs,
        &XxMessage::Message1(message.clone()),
    )?;
    let outbound = handshake.write_message(
        crypto,
        HandshakeHeader {
            sender: fsm.identity.xid,
            recipient: header.sender,
        },
        message.meta,
    )?;

    if let Some(entry) = fsm.peer.as_mut() {
        entry.session = ConnectionState::Handshaking(HandshakeState {
            id: message.meta.handshake_id,
            deadline: fsm.state.now.instant + fsm.config.handshake_timeout,
            mode: HandshakeMode::XxResponder(handshake),
            initial_ephemeral: None,
        });
    }
    fsm.state.handshake = None;
    enqueue_handshake(fsm, header.sender, xx_payload(outbound));
    emit_peer_status(fsm);
    Ok(())
}

pub fn handle_xx2(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    header: HandshakeHeader,
    message: &Xx2,
) -> Result<(), QlFsmError> {
    ensure_bound_peer(fsm, header.sender)?;
    let session = match fsm.peer.as_ref() {
        Some(entry) => entry.session.clone(),
        None => return Ok(()),
    };
    let ConnectionState::Handshaking(HandshakeState {
        id,
        deadline,
        mode: HandshakeMode::XxInitiator(mut handshake),
        initial_ephemeral,
    }) = session
    else {
        return Ok(());
    };

    match handshake.read_message(
        crypto,
        header,
        fsm.state.now.unix_secs,
        &XxMessage::Message2(message.clone()),
    ) {
        Ok(()) => {}
        Err(WireError::InvalidState) => return Ok(()),
        Err(error) => return Err(error.into()),
    }

    let outbound = handshake.write_message(
        crypto,
        HandshakeHeader {
            sender: fsm.identity.xid,
            recipient: header.sender,
        },
        message.meta,
    )?;
    if let Some(entry) = fsm.peer.as_mut() {
        entry.session = ConnectionState::Handshaking(HandshakeState {
            id,
            deadline,
            mode: HandshakeMode::XxInitiator(handshake),
            initial_ephemeral,
        });
    }
    enqueue_handshake(fsm, header.sender, xx_payload(outbound));
    Ok(())
}

pub fn handle_xx3(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    header: HandshakeHeader,
    message: &Xx3,
) -> Result<(), QlFsmError> {
    ensure_bound_peer(fsm, header.sender)?;
    let session = match fsm.peer.as_ref() {
        Some(entry) => entry.session.clone(),
        None => return Ok(()),
    };
    let ConnectionState::Handshaking(HandshakeState {
        mode: HandshakeMode::XxResponder(mut handshake),
        ..
    }) = session
    else {
        return Ok(());
    };

    match handshake.read_message(
        crypto,
        header,
        fsm.state.now.unix_secs,
        &XxMessage::Message3(message.clone()),
    ) {
        Ok(()) => {}
        Err(WireError::InvalidState) => return Ok(()),
        Err(error) => return Err(error.into()),
    }

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
    enqueue_handshake(fsm, header.sender, xx_payload(outbound));
    Ok(())
}

pub fn handle_xx4(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    header: HandshakeHeader,
    message: &Xx4,
) -> Result<(), QlFsmError> {
    ensure_bound_peer(fsm, header.sender)?;
    let session = match fsm.peer.as_ref() {
        Some(entry) => entry.session.clone(),
        None => return Ok(()),
    };
    let ConnectionState::Handshaking(HandshakeState {
        mode: HandshakeMode::XxInitiator(mut handshake),
        ..
    }) = session
    else {
        return Ok(());
    };

    match handshake.read_message(
        crypto,
        header,
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

fn xx_payload(message: XxMessage) -> HandshakePayload {
    match message {
        XxMessage::Message1(message) => HandshakePayload::Xx1(message),
        XxMessage::Message2(message) => HandshakePayload::Xx2(message),
        XxMessage::Message3(message) => HandshakePayload::Xx3(message),
        XxMessage::Message4(message) => HandshakePayload::Xx4(message),
    }
}
