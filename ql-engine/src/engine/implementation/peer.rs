use super::*;

pub fn handle_bind_peer(engine: &mut Engine, peer: Peer) {
    if let Some(peer) = engine.peer.as_ref().map(|existing| existing.peer) {
        engine
            .state
            .pending_events
            .push_back(EngineEvent::PeerStatusChanged {
                peer,
                session: PeerSession::Disconnected,
            });
    }
    bind_peer_record(engine, peer);
}

pub fn handle_pair_local(engine: &mut Engine, crypto: &impl QlCrypto) {
    let now = engine.state.now;
    let Some(peer) = engine.peer.as_ref() else {
        return;
    };
    let meta = engine.next_control_meta(engine.config.packet_expiration);
    let Ok(record) = wire::pair::build_pair_request(
        &engine.identity,
        crypto,
        peer.peer,
        &peer.encapsulation_key,
        meta,
    ) else {
        return;
    };
    let token = engine.state.next_token();
    engine.state.enqueue_handshake_message(
        &engine.config,
        token,
        now + engine.config.packet_expiration,
        wire::encode_record(&record),
    );
}

pub fn handle_unpair_local(engine: &mut Engine) {
    let now = engine.state.now;
    let Some(peer) = engine.peer.as_ref().map(|peer| peer.peer) else {
        return;
    };
    let meta = engine.next_control_meta(engine.config.packet_expiration);
    let record = wire::unpair::build_unpair_record(
        &engine.identity,
        QlHeader {
            sender: engine.identity.xid,
            recipient: peer,
        },
        meta,
    );
    unpair_peer(engine);
    let token = engine.state.next_token();
    engine.state.enqueue_handshake_message(
        &engine.config,
        token,
        now + engine.config.packet_expiration,
        wire::encode_record(&record),
    );
}

pub fn handle_pairing(
    engine: &mut Engine,
    header: &QlHeader,
    request: &mut wire::pair::ArchivedPairRequestRecord,
    crypto: &impl QlCrypto,
) {
    let payload = match wire::pair::decrypt_pair_request(&engine.identity, header, request) {
        Ok(payload) => payload,
        Err(_) => return,
    };
    let peer = XID::new(SigningPublicKey::MLDSA(payload.signing_pub_key.clone()));
    if engine.is_replayed_control(peer, payload.meta) {
        return;
    }
    if let Some(existing) = engine.peer.as_ref() {
        if existing.peer != peer
            || existing.signing_key != payload.signing_pub_key
            || existing.encapsulation_key != payload.encapsulation_pub_key
        {
            return;
        }
    } else {
        bind_peer_record(
            engine,
            Peer {
                peer,
                signing_key: payload.signing_pub_key,
                encapsulation_key: payload.encapsulation_pub_key,
            },
        );
    }
    handshake::handle_connect(engine, crypto);
}

pub fn handle_unpair(
    engine: &mut Engine,
    peer: XID,
    header: &QlHeader,
    record: &wire::unpair::ArchivedUnpairRecord,
) {
    {
        let Some(peer_record) = engine.peer.as_ref() else {
            return;
        };
        if wire::unpair::verify_unpair_record(header, record, &peer_record.signing_key).is_err() {
            return;
        }
    }
    let meta: ControlMeta = (&record.meta).into();
    if engine.is_replayed_control(peer, meta) {
        return;
    }
    unpair_peer(engine);
}

fn bind_peer_record(engine: &mut Engine, peer: Peer) {
    reset_runtime(engine, QlError::Cancelled);
    engine.peer = Some(PeerRecord::new(
        peer.peer,
        peer.signing_key,
        peer.encapsulation_key,
    ));
    engine.emit_peer_status();
    if let Some(peer) = engine.peer.as_ref().map(PeerRecord::snapshot) {
        engine
            .state
            .pending_events
            .push_back(EngineEvent::PersistPeer(peer));
    }
}

fn reset_runtime(engine: &mut Engine, error: QlError) {
    engine.abort_streams(error);
    engine.state.control_outbound.clear();
    engine.state.active_writes.clear();
    engine.state.timeouts.clear();
}

fn unpair_peer(engine: &mut Engine) {
    let Some(peer) = engine.peer.as_ref().map(|peer| peer.peer) else {
        return;
    };
    engine.drop_outbound();
    engine.abort_streams(QlError::SendFailed);
    engine.peer = None;
    engine
        .state
        .pending_events
        .push_back(EngineEvent::PeerStatusChanged {
            peer,
            session: PeerSession::Disconnected,
        });
    engine
        .state
        .pending_events
        .push_back(EngineEvent::ClearPeer);
}
