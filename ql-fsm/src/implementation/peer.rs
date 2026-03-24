use ql_wire::{self as wire, PairRequestRecordWire, QlCrypto, QlHeader, RefMut, UnpairWire};

use super::{
    clear_bound_peer, emit_peer_status, handshake, is_replayed_control, next_control_meta,
    reset_session,
};
use crate::{state::PeerRecord, Peer, QlFsm, QlFsmError, QlFsmEvent};

pub fn handle_bind_peer(fsm: &mut QlFsm, peer: Peer) {
    bind_peer_record(fsm, peer);
}

pub fn handle_pair_local(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
    let meta = next_control_meta(fsm, fsm.config.control_expiration);
    let peer = fsm.peer.as_ref().ok_or(QlFsmError::NoPeerBound)?;
    let record = wire::build_pair_request(
        crypto,
        &fsm.identity,
        peer.peer.xid,
        &peer.peer.encapsulation_key,
        meta,
    );
    fsm.state.outbound.push_back(record);
    Ok(())
}

pub fn handle_unpair_local(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Option<wire::QlRecord> {
    let peer = fsm.peer.as_ref()?.peer.clone();
    let meta = next_control_meta(fsm, fsm.config.control_expiration);
    let record = wire::build_unpair(
        crypto,
        &fsm.identity,
        peer.xid,
        meta,
    );
    clear_bound_peer(fsm);
    Some(record)
}

pub fn handle_pair(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    header: &QlHeader,
    request: &mut RefMut<'_, PairRequestRecordWire>,
) -> Result<(), QlFsmError> {
    let payload = wire::decrypt_pair_request(
        crypto,
        &fsm.identity,
        header,
        request,
        fsm.state.now.unix_secs,
    )?;
    let peer = Peer {
        xid: payload.xid,
        signing_key: payload.signing_pub_key,
        encapsulation_key: payload.encapsulation_pub_key,
    };
    if is_replayed_control(fsm, peer.xid, payload.meta) {
        return Ok(());
    }

    match fsm.peer.as_ref() {
        Some(existing) if existing.peer != peer => return Err(QlFsmError::InvalidXid),
        Some(_) => {}
        None => bind_peer_record(fsm, peer.clone()),
    }

    handshake::handle_connect(fsm, crypto)
}

pub fn handle_unpair(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    header: &QlHeader,
    unpair: &RefMut<'_, UnpairWire>,
) -> Result<(), QlFsmError> {
    let Some(entry) = fsm.peer.as_ref() else {
        return Ok(());
    };

    wire::verify_unpair(
        crypto,
        header,
        &entry.peer.signing_key,
        unpair,
        fsm.state.now.unix_secs,
    )?;
    if is_replayed_control(fsm, header.sender, wire::ControlMeta::from_wire(unpair.meta)) {
        return Ok(());
    }

    clear_bound_peer(fsm);
    Ok(())
}

fn bind_peer_record(fsm: &mut QlFsm, peer: Peer) {
    fsm.peer = Some(PeerRecord::new(peer.clone()));
    reset_session(fsm);
    fsm.state.events.push_back(QlFsmEvent::NewPeer(peer));
    emit_peer_status(fsm);
}
