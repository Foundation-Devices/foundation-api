use ql_wire::{self as wire, pair::ArchivedPairRequestRecord, QlCrypto, QlHeader};

use super::{emit_peer_status, handshake, is_replayed_control, next_control_meta, reset_session};
use crate::{state::PeerRecord, Peer, QlFsm, QlFsmError, QlFsmEvent};

pub fn handle_bind_peer(fsm: &mut QlFsm, peer: Peer) {
    bind_peer_record(fsm, peer);
}

pub fn handle_pair_local(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
    let meta = next_control_meta(fsm, fsm.config.control_expiration);
    let peer = fsm.peer.as_ref().ok_or(QlFsmError::NoPeerBound)?;
    let record = wire::pair::build_pair_request(
        crypto,
        &fsm.identity,
        peer.peer.xid,
        &peer.peer.encapsulation_key,
        meta,
    )?;
    fsm.state.outbound.push_back(record);
    Ok(())
}

pub fn handle_pair(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    header: &QlHeader,
    request: &mut ArchivedPairRequestRecord,
) -> Result<(), QlFsmError> {
    let payload = match wire::pair::decrypt_pair_request(
        crypto,
        &fsm.identity,
        header,
        request,
        fsm.state.now.unix_secs,
    ) {
        Ok(payload) => payload,
        Err(_) => return Ok(()),
    };
    let peer = Peer {
        xid: payload.xid,
        signing_key: payload.signing_pub_key,
        encapsulation_key: payload.encapsulation_pub_key,
    };
    if is_replayed_control(fsm, peer.xid, payload.meta) {
        return Ok(());
    }

    match fsm.peer.as_ref() {
        Some(existing) if existing.peer != peer => return Ok(()),
        Some(_) => {}
        None => bind_peer_record(fsm, peer.clone()),
    }

    handshake::handle_connect(fsm, crypto)
}

fn bind_peer_record(fsm: &mut QlFsm, peer: Peer) {
    fsm.peer = Some(PeerRecord::new(peer.clone()));
    reset_session(fsm);
    fsm.state.events.push_back(QlFsmEvent::NewPeer(peer));
    emit_peer_status(fsm);
}
