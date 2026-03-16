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
        token: Token,
        reply: wire::handshake::HelloReply,
        deadline: Instant,
    },
    Ignore,
}

enum HelloReplyAction {
    Advance {
        hello: wire::handshake::Hello,
        responder_signing_key: bc_components::MLDSAPublicKey,
        initiator_secret: SymmetricKey,
    },
    ResendConfirm {
        token: Token,
        confirm: wire::handshake::Confirm,
        deadline: Instant,
    },
}

pub fn handle_connect(
    engine: &mut Engine,
    now: Instant,
    crypto: &impl QlCrypto,
    events: &mut impl EngineEventSink,
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
        engine.emit_peer_status(events);
    }
}

pub fn handle_hello(
    engine: &mut Engine,
    now: Instant,
    peer: XID,
    hello: &wire::handshake::ArchivedHello,
    crypto: &impl QlCrypto,
    events: &mut impl EngineEventSink,
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
                    handshake_token,
                    hello: stored,
                    reply,
                    deadline,
                    stage: HandshakeResponder::WaitingConfirm { .. },
                } => {
                    if same_hello(stored, hello) {
                        HelloAction::ResendReply {
                            token: *handshake_token,
                            reply: reply.clone(),
                            deadline: *deadline,
                        }
                    } else {
                        HelloAction::StartResponder
                    }
                }
                PeerSession::Responder { .. }
                | PeerSession::Disconnected
                | PeerSession::Connected { .. } => HelloAction::StartResponder,
            }
        }
        None => return,
    };

    match action {
        HelloAction::StartResponder => {
            let meta: ControlMeta = (&hello.meta).into();
            if engine.is_replayed_control(peer, meta) {
                return;
            }
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
                engine.emit_peer_status(events);
            }
        }
        HelloAction::ResendReply {
            token,
            reply,
            deadline,
        } => {
            if engine.handshake_write_pending(token) {
                return;
            }
            engine.clear_handshake_retry_at(token);
            enqueue_handshake_record(
                engine,
                token,
                deadline,
                peer,
                HandshakeRecord::HelloReply(reply),
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
) {
    let action = {
        let Some(peer_record) = engine.peer.as_ref() else {
            return;
        };
        let PeerSession::Initiator {
            handshake_token,
            hello,
            session_key,
            stage,
            deadline,
            ..
        } = &peer_record.session
        else {
            return;
        };
        match stage {
            HandshakeInitiator::WaitingHelloReply { .. } => HelloReplyAction::Advance {
                hello: hello.clone(),
                responder_signing_key: peer_record.signing_key.clone(),
                initiator_secret: session_key.clone(),
            },
            HandshakeInitiator::WaitingReady {
                reply: stored_reply,
                confirm,
                ..
            } if same_reply(stored_reply, reply) => HelloReplyAction::ResendConfirm {
                token: *handshake_token,
                confirm: confirm.clone(),
                deadline: *deadline,
            },
            HandshakeInitiator::WaitingReady { .. } => return,
        }
    };
    match action {
        HelloReplyAction::Advance {
            hello,
            responder_signing_key,
            initiator_secret,
        } => {
            let confirm_meta = engine.next_control_meta(engine.config.handshake_timeout);
            let (confirm, session_key) = match wire::handshake::build_confirm(
                &engine.identity,
                peer,
                &responder_signing_key,
                &hello,
                reply,
                &initiator_secret,
                confirm_meta,
            ) {
                Ok(result) => result,
                Err(_) => return,
            };
            let reply_meta: ControlMeta = (&reply.meta).into();
            if engine.is_replayed_control(peer, reply_meta) {
                return;
            }
            let Ok(reply) = wire::deserialize_value(reply) else {
                return;
            };
            let deadline = now + engine.config.handshake_timeout;
            let token = engine.state.next_token();
            let Some(peer_record) = engine.peer.as_mut() else {
                return;
            };
            peer_record.session = PeerSession::Initiator {
                handshake_token: token,
                hello,
                session_key,
                deadline,
                stage: HandshakeInitiator::WaitingReady {
                    reply,
                    confirm: confirm.clone(),
                    retry_count: 0,
                    retry_at: None,
                },
            };
            enqueue_handshake_record(
                engine,
                token,
                deadline,
                peer,
                HandshakeRecord::Confirm(confirm),
            );
        }
        HelloReplyAction::ResendConfirm {
            token,
            confirm,
            deadline,
        } => {
            if engine.handshake_write_pending(token) {
                return;
            }
            engine.clear_handshake_retry_at(token);
            enqueue_handshake_record(
                engine,
                token,
                deadline,
                peer,
                HandshakeRecord::Confirm(confirm),
            );
        }
    }
}

pub fn handle_confirm(
    engine: &mut Engine,
    now: Instant,
    peer: XID,
    confirm: &wire::handshake::ArchivedConfirm,
    crypto: &impl QlCrypto,
) {
    if let Some((ready, deadline, token)) = current_ready_resend(engine, now, peer, confirm) {
        if engine.handshake_write_pending(token) {
            return;
        }
        enqueue_handshake_record(engine, token, deadline, peer, HandshakeRecord::Ready(ready));
        return;
    }
    if let Some(ready) = recent_ready_resend(engine, now, peer, confirm) {
        let record = QlRecord {
            header: QlHeader {
                sender: engine.identity.xid,
                recipient: peer,
            },
            payload: QlPayload::Handshake(HandshakeRecord::Ready(ready)),
        };
        engine
            .state
            .enqueue_control(&engine.config, true, wire::encode_record(&record));
        return;
    }

    let res = {
        let Some(peer_record) = engine.peer.as_ref() else {
            return;
        };
        let PeerSession::Responder {
            hello,
            reply,
            stage,
            ..
        } = &peer_record.session
        else {
            return;
        };
        let HandshakeResponder::WaitingConfirm { secrets, .. } = stage else {
            return;
        };

        wire::handshake::finalize_confirm(
            peer,
            engine.identity.xid,
            &peer_record.signing_key,
            hello,
            reply,
            confirm,
            secrets,
        )
        .map(|session_key| (hello.clone(), reply.clone(), session_key))
    };

    match res {
        Ok((hello, reply, session_key)) => {
            let meta: ControlMeta = (&confirm.meta).into();
            if engine.is_replayed_control(peer, meta) {
                return;
            }
            let deadline = now + engine.config.handshake_timeout;
            let ready_meta = engine.next_control_meta(engine.config.handshake_timeout);
            let ready = wire::handshake::build_ready(
                QlHeader {
                    sender: engine.identity.xid,
                    recipient: peer,
                },
                &session_key,
                ready_meta,
                encrypted_message_nonce(crypto),
            );
            let token = engine.state.next_token();
            if let Some(peer_record) = engine.peer.as_mut() {
                peer_record.session = PeerSession::Responder {
                    handshake_token: token,
                    hello,
                    reply,
                    deadline,
                    stage: HandshakeResponder::SendingReady {
                        session_key,
                        ready: ready.clone(),
                    },
                };
            }
            enqueue_handshake_record(engine, token, deadline, peer, HandshakeRecord::Ready(ready));
        }
        Err(_) => {}
    }
}

pub fn handle_ready(
    engine: &mut Engine,
    now: Instant,
    peer: XID,
    header: &QlHeader,
    ready: &mut wire::handshake::ArchivedReady,
    events: &mut impl EngineEventSink,
) {
    let session_key = {
        let Some(peer_record) = engine.peer.as_ref() else {
            return;
        };
        let PeerSession::Initiator {
            session_key, stage, ..
        } = &peer_record.session
        else {
            return;
        };
        let HandshakeInitiator::WaitingReady { .. } = stage else {
            return;
        };
        session_key.clone()
    };

    let Ok(body) = wire::handshake::decrypt_ready(header, ready, &session_key) else {
        return;
    };
    if engine.is_replayed_control(peer, body.meta) {
        return;
    }

    if let Some(peer_record) = engine.peer.as_mut() {
        peer_record.session = PeerSession::Connected {
            session_key,
            keepalive: KeepAliveState::default(),
            recent_ready: None,
        };
    }
    engine.record_activity(now);
    engine.emit_peer_status(events);
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
        stage: HandshakeInitiator::WaitingHelloReply {
            retry_count: 0,
            retry_at: None,
        },
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
        deadline,
        stage: HandshakeResponder::WaitingConfirm {
            secrets,
            retry_count: 0,
            retry_at: None,
        },
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

pub(super) fn enqueue_handshake_record(
    engine: &mut Engine,
    token: Token,
    deadline: Instant,
    peer: XID,
    record: HandshakeRecord,
) {
    let record = QlRecord {
        header: QlHeader {
            sender: engine.identity.xid,
            recipient: peer,
        },
        payload: QlPayload::Handshake(record),
    };
    engine.state.enqueue_handshake_message(
        &engine.config,
        token,
        deadline,
        wire::encode_record(&record),
    );
}

fn same_hello(stored: &wire::handshake::Hello, incoming: &wire::handshake::ArchivedHello) -> bool {
    let meta: ControlMeta = (&incoming.meta).into();
    stored.meta.packet_id == meta.packet_id && stored.nonce == (&incoming.nonce).into()
}

fn same_reply(
    stored: &wire::handshake::HelloReply,
    incoming: &wire::handshake::ArchivedHelloReply,
) -> bool {
    let meta: ControlMeta = (&incoming.meta).into();
    stored.meta.packet_id == meta.packet_id && stored.nonce == (&incoming.nonce).into()
}

fn current_ready_resend(
    engine: &Engine,
    now: Instant,
    peer: XID,
    confirm: &wire::handshake::ArchivedConfirm,
) -> Option<(wire::handshake::Ready, Instant, Token)> {
    let peer_record = engine.peer.as_ref()?;
    let PeerSession::Responder {
        handshake_token,
        hello,
        reply,
        deadline,
        stage: HandshakeResponder::SendingReady { ready, .. },
    } = &peer_record.session
    else {
        return None;
    };
    if *deadline <= now {
        return None;
    }
    wire::handshake::verify_confirm(
        peer,
        engine.identity.xid,
        &peer_record.signing_key,
        hello,
        reply,
        confirm,
    )
    .ok()?;
    Some((ready.clone(), *deadline, *handshake_token))
}

fn recent_ready_resend(
    engine: &Engine,
    now: Instant,
    peer: XID,
    confirm: &wire::handshake::ArchivedConfirm,
) -> Option<wire::handshake::Ready> {
    let peer_record = engine.peer.as_ref()?;
    let PeerSession::Connected {
        recent_ready: Some(recent_ready),
        ..
    } = &peer_record.session
    else {
        return None;
    };
    if recent_ready.expires_at <= now {
        return None;
    }
    wire::handshake::verify_confirm(
        peer,
        engine.identity.xid,
        &peer_record.signing_key,
        &recent_ready.hello,
        &recent_ready.reply,
        confirm,
    )
    .ok()?;
    Some(recent_ready.ready.clone())
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
