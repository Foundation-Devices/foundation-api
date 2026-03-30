mod kk;
mod xx;

use std::cmp::Ordering;

use ql_wire::{
    self as wire, EphemeralPublicKey, HandshakeHeader, HandshakeMeta, HandshakePayload, QlCrypto,
    QlHandshakeRecord, XID,
};

use super::{emit_peer_status, fail_pending_connect_session, reset_session};
use crate::{
    state::{ConnectionState, HandshakeMode, HandshakeState, SessionTransport},
    Peer, QlFsm, QlFsmError,
};

pub fn handle_connect(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
    let Some(peer) = fsm.peer.as_ref().map(|entry| entry.peer.clone()) else {
        return Err(QlFsmError::NoPeerBound);
    };
    if !matches!(
        fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Disconnected)
    ) {
        return Ok(());
    }

    match &peer.bundle {
        Some(bundle) => kk::start_initiator(fsm, crypto, peer.xid, bundle.clone()),
        None => xx::start_initiator(fsm, crypto, peer.xid),
    }
}

pub fn next_handshake_meta(fsm: &mut QlFsm) -> wire::HandshakeMeta {
    let handshake_id = wire::HandshakeId(fsm.state.next_control_id);
    fsm.state.next_control_id = fsm.state.next_control_id.wrapping_add(1);
    wire::HandshakeMeta {
        handshake_id,
        valid_until: super::deadline_after_secs(
            fsm.state.now.unix_secs,
            fsm.config.handshake_timeout,
        ),
    }
}

pub fn enqueue_handshake(fsm: &mut QlFsm, peer: XID, payload: HandshakePayload) {
    debug_assert!(fsm.state.handshake.is_none());
    fsm.state.handshake = Some(QlHandshakeRecord {
        header: HandshakeHeader {
            sender: fsm.identity.xid,
            recipient: peer,
        },
        payload,
    });
}

pub fn is_replayed_handshake_start(fsm: &mut QlFsm, peer: XID, meta: HandshakeMeta) -> bool {
    fsm.state
        .replay_cache
        .check_and_store_valid_until(peer, meta, fsm.state.now.unix_secs)
}

pub fn handle_handshake_record(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    record: &QlHandshakeRecord,
) -> Result<(), QlFsmError> {
    if record.header.recipient != fsm.identity.xid {
        return Err(QlFsmError::InvalidXid);
    }

    match &record.payload {
        HandshakePayload::Xx1(message) => xx::handle_xx1(fsm, crypto, record.header, message),
        HandshakePayload::Xx2(message) => xx::handle_xx2(fsm, crypto, record.header, message),
        HandshakePayload::Xx3(message) => xx::handle_xx3(fsm, crypto, record.header, message),
        HandshakePayload::Xx4(message) => xx::handle_xx4(fsm, crypto, record.header, message),
        HandshakePayload::Kk1(message) => kk::handle_kk1(fsm, crypto, record.header, message),
        HandshakePayload::Kk2(message) => kk::handle_kk2(fsm, crypto, record.header, message),
    }
}

pub fn handle_timer(fsm: &mut QlFsm) {
    let timed_out = matches!(
        fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Handshaking(HandshakeState { deadline, .. }))
            if *deadline <= fsm.state.now.instant
    );

    if !timed_out {
        return;
    }

    if let Some(entry) = fsm.peer.as_mut() {
        entry.session = ConnectionState::Disconnected;
    }
    fsm.state.handshake = None;
    fail_pending_connect_session(fsm, ql_wire::CloseCode::TIMEOUT);
    emit_peer_status(fsm);
}

pub fn next_handshake_deadline(fsm: &QlFsm) -> Option<std::time::Instant> {
    match fsm.peer.as_ref().map(|entry| &entry.session) {
        Some(ConnectionState::Handshaking(HandshakeState { deadline, .. })) => Some(*deadline),
        _ => None,
    }
}

fn ensure_or_bind_peer(
    fsm: &mut QlFsm,
    xid: XID,
    bundle: Option<wire::PeerBundle>,
) -> Result<(), QlFsmError> {
    match fsm.peer.as_ref() {
        Some(entry) if entry.peer.xid == xid => Ok(()),
        Some(_) => Err(QlFsmError::InvalidXid),
        None => {
            super::handle_bind_peer(fsm, Peer { xid, bundle });
            Ok(())
        }
    }
}

fn ensure_bound_peer(fsm: &QlFsm, xid: XID) -> Result<(), QlFsmError> {
    match fsm.peer.as_ref() {
        Some(entry) if entry.peer.xid == xid => Ok(()),
        Some(_) => Err(QlFsmError::InvalidXid),
        None => Ok(()),
    }
}

fn ensure_bound_peer_with_bundle(fsm: &QlFsm, xid: XID) -> Result<(), QlFsmError> {
    match fsm.peer.as_ref() {
        Some(entry) if entry.peer.xid == xid && entry.peer.bundle.is_some() => Ok(()),
        Some(entry) if entry.peer.xid == xid => Err(QlFsmError::InvalidPayload),
        Some(_) => Err(QlFsmError::InvalidXid),
        None => Err(QlFsmError::NoPeerBound),
    }
}

fn finish_handshake(
    fsm: &mut QlFsm,
    transport: SessionTransport,
    remote_bundle: wire::PeerBundle,
) -> Result<(), QlFsmError> {
    let Some(entry) = fsm.peer.as_mut() else {
        return Err(QlFsmError::NoPeerBound);
    };

    match &entry.peer.bundle {
        Some(existing) if existing != &remote_bundle => return Err(QlFsmError::InvalidPayload),
        Some(_) => {}
        None => entry.peer.bundle = Some(remote_bundle),
    }

    entry.session = ConnectionState::Connected(transport);
    emit_peer_status(fsm);
    Ok(())
}

fn reset_connected_session_if_needed(fsm: &mut QlFsm) {
    if matches!(
        fsm.peer.as_ref().map(|entry| &entry.session),
        Some(ConnectionState::Connected(_))
    ) {
        reset_session(fsm);
    }
}

fn should_ignore_inbound_handshake_start(
    fsm: &QlFsm,
    sender: XID,
    inbound_xx: bool,
    inbound_ephemeral: &EphemeralPublicKey,
) -> bool {
    let Some(entry) = fsm.peer.as_ref() else {
        return false;
    };
    if entry.peer.xid != sender {
        return false;
    }

    let ConnectionState::Handshaking(HandshakeState {
        mode,
        initial_ephemeral: Some(local_ephemeral),
        ..
    }) = &entry.session
    else {
        return false;
    };

    match (mode, inbound_xx) {
        (HandshakeMode::KkInitiator(_), true) => false,
        (HandshakeMode::XxInitiator(_), false) => true,
        (HandshakeMode::XxInitiator(_), true) | (HandshakeMode::KkInitiator(_), false) => {
            match inbound_ephemeral
                .mlkem_public_key
                .as_bytes()
                .cmp(local_ephemeral.mlkem_public_key.as_bytes())
            {
                Ordering::Less => false,
                Ordering::Greater => true,
                Ordering::Equal => sender.0.cmp(&fsm.identity.xid.0) != Ordering::Less,
            }
        }
        _ => false,
    }
}
