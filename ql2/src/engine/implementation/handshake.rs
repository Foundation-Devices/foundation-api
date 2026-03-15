use super::*;
use crate::{
    engine::{EngineConfig, EngineState, KeepAliveState},
    identity::QlIdentity,
    wire::{handshake::HandshakeRecord, QlPayload, QlRecord},
};

#[derive(Debug)]
enum HelloAction {
    StartResponder,
    ResendReply {
        reply: wire::handshake::HelloReply,
        deadline: Instant,
    },
    Ignore,
}

pub fn handle_connect(
    engine: &mut Engine,
    now: Instant,
    crypto: &impl QlCrypto,
    emit: &mut impl OutputFn,
) {
    let Some(_) = engine.peer.as_ref() else {
        return;
    };
    let started = {
        let config = &engine.config;
        let identity = &engine.identity;
        let state = &mut engine.state;
        let Some(peer_record) = engine.peer.as_mut() else {
            return;
        };
        start_initiator_handshake(config, identity, state, peer_record, now, crypto)
    };
    if started {
        engine.emit_peer_status(emit);
    }
}

pub fn handle_hello(
    engine: &mut Engine,
    now: Instant,
    peer: XID,
    hello: &wire::handshake::ArchivedHello,
    crypto: &impl QlCrypto,
    emit: &mut impl OutputFn,
) {
    let action = match engine.peer.as_ref() {
        Some(entry) => {
            if wire::handshake::verify_hello(peer, engine.identity.xid, &entry.signing_key, hello)
                .is_err()
            {
                return;
            }
            match &entry.session {
                PeerSession::Initiator {
                    hello: local_hello, ..
                } => {
                    if peer_hello_wins(local_hello, engine.identity.xid, hello, peer) {
                        HelloAction::StartResponder
                    } else {
                        HelloAction::Ignore
                    }
                }
                PeerSession::Responder {
                    hello: stored,
                    reply,
                    deadline,
                    ..
                } => {
                    if stored.nonce == (&hello.nonce).into() {
                        HelloAction::ResendReply {
                            reply: reply.clone(),
                            deadline: *deadline,
                        }
                    } else {
                        HelloAction::StartResponder
                    }
                }
                PeerSession::Disconnected | PeerSession::Connected { .. } => {
                    HelloAction::StartResponder
                }
            }
        }
        None => return,
    };
    let meta: ControlMeta = (&hello.meta).into();
    if engine.is_replayed_control(peer, meta) {
        return;
    }

    match action {
        HelloAction::StartResponder => {
            let changed = {
                let config = &engine.config;
                let identity = &engine.identity;
                let state = &mut engine.state;
                let Some(peer_record) = engine.peer.as_mut() else {
                    return;
                };
                start_responder_handshake(
                    config,
                    identity,
                    state,
                    peer_record,
                    now,
                    peer,
                    hello,
                    crypto,
                )
            };
            if changed {
                engine.emit_peer_status(emit);
            }
        }
        HelloAction::ResendReply { reply, deadline } => {
            let record = QlRecord {
                header: QlHeader {
                    sender: engine.identity.xid,
                    recipient: peer,
                },
                payload: QlPayload::Handshake(HandshakeRecord::HelloReply(reply)),
            };
            let token = engine.state.next_token();
            engine.state.enqueue_handshake_message(
                &engine.config,
                token,
                deadline,
                wire::encode_record(&record),
            );
        }
        HelloAction::Ignore => {}
    }
}

pub fn handle_hello_reply(
    engine: &mut Engine,
    now: Instant,
    peer: XID,
    reply: &wire::handshake::ArchivedHelloReply,
    emit: &mut impl OutputFn,
) {
    let deadline = now + engine.config.handshake_timeout;
    let confirm_meta = engine.next_control_meta(engine.config.handshake_timeout);
    let res = {
        let Some(peer_record) = engine.peer.as_ref() else {
            return;
        };
        let PeerSession::Initiator {
            hello,
            session_key,
            stage,
            ..
        } = &peer_record.session
        else {
            return;
        };
        if *stage != InitiatorStage::WaitingHelloReply {
            return;
        }
        wire::handshake::build_confirm(
            &engine.identity,
            peer,
            &peer_record.signing_key,
            hello,
            reply,
            session_key,
            confirm_meta,
        )
        .map(|(confirm, session_key)| (hello.clone(), confirm, session_key))
    };
    let (hello, confirm, session_key) = match res {
        Ok(result) => result,
        Err(_) => {
            if let Some(peer_record) = engine.peer.as_mut() {
                peer_record.session = PeerSession::Disconnected;
            }
            engine.emit_peer_status(emit);
            return;
        }
    };
    let reply_meta: ControlMeta = (&reply.meta).into();
    if engine.is_replayed_control(peer, reply_meta) {
        return;
    }
    let config = &engine.config;
    let state = &mut engine.state;
    let token = state.next_token();
    let Some(peer_record) = engine.peer.as_mut() else {
        return;
    };
    peer_record.session = PeerSession::Initiator {
        handshake_token: token,
        hello,
        session_key,
        deadline,
        stage: InitiatorStage::SendingConfirm,
    };

    let record = QlRecord {
        header: QlHeader {
            sender: engine.identity.xid,
            recipient: peer,
        },
        payload: QlPayload::Handshake(HandshakeRecord::Confirm(confirm)),
    };
    state.enqueue_handshake_message(config, token, deadline, wire::encode_record(&record));
}

pub fn handle_confirm(
    engine: &mut Engine,
    now: Instant,
    peer: XID,
    confirm: &wire::handshake::ArchivedConfirm,
    emit: &mut impl OutputFn,
) {
    let Some(peer_record) = engine.peer.as_ref() else {
        return;
    };
    let PeerSession::Responder {
        hello,
        reply,
        secrets,
        ..
    } = &peer_record.session
    else {
        return;
    };

    match wire::handshake::finalize_confirm(
        peer,
        engine.identity.xid,
        &peer_record.signing_key,
        hello,
        reply,
        confirm,
        secrets,
    ) {
        Ok(session_key) => {
            let meta: ControlMeta = (&confirm.meta).into();
            if engine.is_replayed_control(peer, meta) {
                return;
            }
            if let Some(peer_record) = engine.peer.as_mut() {
                peer_record.session = PeerSession::Connected {
                    session_key,
                    keepalive: KeepAliveState::default(),
                };
            }
            engine.record_activity(now);
            engine.emit_peer_status(emit);
        }
        Err(_) => {
            if let Some(peer_record) = engine.peer.as_mut() {
                peer_record.session = PeerSession::Disconnected;
            }
            engine.emit_peer_status(emit);
        }
    }
}

fn start_initiator_handshake(
    config: &EngineConfig,
    identity: &QlIdentity,
    state: &mut EngineState,
    peer_record: &mut PeerRecord,
    now: Instant,
    crypto: &impl QlCrypto,
) -> bool {
    if !matches!(peer_record.session, PeerSession::Disconnected) {
        return false;
    }

    let meta = ControlMeta {
        packet_id: state.next_packet_id(),
        valid_until: wire::now_secs() + config.handshake_timeout.as_secs(),
    };
    let peer = peer_record.peer;
    let Ok((hello, session_key)) =
        wire::handshake::build_hello(identity, crypto, peer, &peer_record.encapsulation_key, meta)
    else {
        return false;
    };

    let deadline = now + config.handshake_timeout;
    let token = state.next_token();
    peer_record.session = PeerSession::Initiator {
        handshake_token: token,
        hello: hello.clone(),
        session_key,
        deadline,
        stage: InitiatorStage::WaitingHelloReply,
    };

    let record = QlRecord {
        header: QlHeader {
            sender: identity.xid,
            recipient: peer,
        },
        payload: QlPayload::Handshake(HandshakeRecord::Hello(hello)),
    };
    state.enqueue_handshake_message(config, token, deadline, wire::encode_record(&record));
    true
}

fn start_responder_handshake(
    config: &EngineConfig,
    identity: &QlIdentity,
    state: &mut EngineState,
    peer_record: &mut PeerRecord,
    now: Instant,
    peer: XID,
    hello: &wire::handshake::ArchivedHello,
    crypto: &impl QlCrypto,
) -> bool {
    let reply_meta = ControlMeta {
        packet_id: state.next_packet_id(),
        valid_until: wire::now_secs() + config.handshake_timeout.as_secs(),
    };
    let (reply, secrets) = match wire::handshake::respond_hello(
        identity,
        crypto,
        peer,
        &peer_record.signing_key,
        &peer_record.encapsulation_key,
        hello,
        reply_meta,
    ) {
        Ok(result) => result,
        Err(_) => {
            peer_record.session = PeerSession::Disconnected;
            return true;
        }
    };
    let Ok(hello) = wire::deserialize_value(hello) else {
        peer_record.session = PeerSession::Disconnected;
        return true;
    };

    let deadline = now + config.handshake_timeout;
    let token = state.next_token();
    peer_record.session = PeerSession::Responder {
        handshake_token: token,
        hello,
        reply: reply.clone(),
        secrets,
        deadline,
    };

    let record = QlRecord {
        header: QlHeader {
            sender: identity.xid,
            recipient: peer,
        },
        payload: QlPayload::Handshake(HandshakeRecord::HelloReply(reply)),
    };
    state.enqueue_handshake_message(config, token, deadline, wire::encode_record(&record));
    true
}

fn peer_hello_wins(
    local_hello: &wire::handshake::Hello,
    local_sender: XID,
    peer_hello: &wire::handshake::ArchivedHello,
    peer_sender: XID,
) -> bool {
    use std::cmp::Ordering;

    let peer_nonce: bc_components::Nonce = (&peer_hello.nonce).into();
    match peer_nonce.data().cmp(local_hello.nonce.data()) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => peer_sender.data().cmp(local_sender.data()) == Ordering::Less,
    }
}
