use super::*;

pub fn handle_bind_peer(engine: &mut Engine, peer: Peer, events: &mut impl EngineEventSink) {
    if let Some(existing) = engine.peer.as_ref() {
        events.peer_status_changed(existing.peer, PeerSession::Disconnected);
    }
    bind_peer_record(engine, peer, events);
}

pub fn handle_pair_local(engine: &mut Engine, now: Instant, crypto: &impl QlCrypto) {
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

pub fn handle_unpair_local(engine: &mut Engine, now: Instant, events: &mut impl EngineEventSink) {
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
    unpair_peer(engine, events);
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
    now: Instant,
    header: &QlHeader,
    request: &mut wire::pair::ArchivedPairRequestRecord,
    crypto: &impl QlCrypto,
    events: &mut impl EngineEventSink,
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
            events,
        );
    }
    handshake::handle_connect(engine, now, crypto, events);
}

pub fn handle_unpair(
    engine: &mut Engine,
    peer: XID,
    header: &QlHeader,
    record: &wire::unpair::ArchivedUnpairRecord,
    events: &mut impl EngineEventSink,
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
    unpair_peer(engine, events);
}

fn bind_peer_record(engine: &mut Engine, peer: Peer, events: &mut impl EngineEventSink) {
    reset_runtime(engine, QlError::Cancelled, events);
    engine.peer = Some(PeerRecord::new(
        peer.peer,
        peer.signing_key,
        peer.encapsulation_key,
    ));
    engine.emit_peer_status(events);
    if let Some(peer) = engine.peer.as_ref() {
        events.persist_peer(peer.snapshot());
    }
}

fn reset_runtime(engine: &mut Engine, error: QlError, events: &mut impl EngineEventSink) {
    engine.abort_streams(error, events);
    engine.state.control_outbound.clear();
    engine.state.active_writes.clear();
    engine.state.timeouts.clear();
}

fn unpair_peer(engine: &mut Engine, events: &mut impl EngineEventSink) {
    let Some(peer) = engine.peer.as_ref().map(|peer| peer.peer) else {
        return;
    };
    engine.drop_outbound();
    engine.abort_streams(QlError::SendFailed, events);
    engine.peer = None;
    events.peer_status_changed(peer, PeerSession::Disconnected);
    events.clear_peer();
}
