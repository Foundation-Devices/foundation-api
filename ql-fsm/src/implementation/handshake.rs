use std::{cmp::Ordering, time::Instant};

use bc_components::{MLDSAPublicKey, SymmetricKey};
use ql_wire::{
    self as wire,
    handshake::{Confirm, Hello, HelloReply, Ready},
    ControlMeta, QlCrypto, QlHeader, XID,
};
use rkyv::api::low;

use crate::{
    state::{ConnectionState, HandshakeInitiator, HandshakeResponder, RecentReady},
    Peer, QlFsm, QlFsmError,
};

#[derive(Debug)]
enum HelloAction {
    StartResponder,
    ResendReply { reply: HelloReply },
    Ignore,
}

#[derive(Debug)]
enum HelloReplyAction {
    Advance {
        hello: Hello,
        initiator_secret: SymmetricKey,
        responder_signing_key: MLDSAPublicKey,
    },
    ResendConfirm {
        confirm: Confirm,
    },
}

#[derive(Debug, Clone)]
enum RetryAction {
    Hello { peer: XID, hello: Hello },
    HelloReply { peer: XID, reply: HelloReply },
    Confirm { peer: XID, confirm: Confirm },
}

pub fn handle_connect(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
    start_initiator_handshake(fsm, crypto)
}

pub fn handle_hello(
    fsm: &mut QlFsm,
    header: &QlHeader,
    archived_hello: &wire::handshake::ArchivedHello,
    crypto: &impl QlCrypto,
) -> Result<(), QlFsmError> {
    let hello: Hello = deserialize_archived(archived_hello)?;
    let action = {
        let Some(entry) = fsm.peer.as_ref() else {
            return Ok(());
        };
        if wire::handshake::verify_hello(
            header.sender,
            fsm.identity.xid,
            &entry.peer.signing_key,
            archived_hello,
        )
        .is_err()
        {
            return Ok(());
        }

        match &entry.session {
            ConnectionState::Initiator {
                hello: local_hello, ..
            } => {
                if peer_hello_wins(local_hello, fsm.identity.xid, &hello, header.sender) {
                    HelloAction::StartResponder
                } else {
                    HelloAction::Ignore
                }
            }
            ConnectionState::Responder {
                hello: stored,
                reply,
                stage: HandshakeResponder::WaitingConfirm { .. },
                ..
            } => {
                if same_hello(stored, &hello) {
                    HelloAction::ResendReply {
                        reply: reply.clone(),
                    }
                } else {
                    HelloAction::StartResponder
                }
            }
            ConnectionState::Disconnected | ConnectionState::Connected { .. } => {
                HelloAction::StartResponder
            }
        }
    };

    match action {
        HelloAction::Ignore => {}
        HelloAction::ResendReply { reply } => {
            fsm.enqueue_handshake(
                header.sender,
                wire::handshake::HandshakeRecord::HelloReply(reply),
            );
        }
        HelloAction::StartResponder => {
            if fsm.is_replayed_control(header.sender, hello.meta) {
                return Ok(());
            }

            let peer = fsm.peer.as_ref().map(|entry| entry.peer.clone()).unwrap();
            let reply_meta = fsm.next_control_meta(fsm.config.handshake_timeout);
            let responder = wire::handshake::respond_hello(
                &fsm.identity,
                crypto,
                peer.xid,
                &peer.signing_key,
                &peer.encapsulation_key,
                archived_hello,
                reply_meta,
            );

            let (reply, secrets) = match responder {
                Ok(result) => result,
                Err(_) => {
                    if let Some(entry) = fsm.peer.as_mut() {
                        entry.session = ConnectionState::Disconnected;
                    }
                    fsm.emit_peer_status();
                    return Ok(());
                }
            };

            let deadline = fsm.state.now.instant + fsm.config.handshake_timeout;
            let retry_at = Some(fsm.state.now.instant + fsm.config.handshake_retry_interval);
            if let Some(entry) = fsm.peer.as_mut() {
                entry.session = ConnectionState::Responder {
                    hello: hello.clone(),
                    reply: reply.clone(),
                    deadline,
                    stage: HandshakeResponder::WaitingConfirm {
                        secrets,
                        retry_count: 0,
                        retry_at,
                    },
                };
            }
            fsm.enqueue_handshake(
                header.sender,
                wire::handshake::HandshakeRecord::HelloReply(reply),
            );
            fsm.emit_peer_status();
        }
    }

    Ok(())
}

pub fn handle_hello_reply(
    fsm: &mut QlFsm,
    header: &QlHeader,
    archived_reply: &wire::handshake::ArchivedHelloReply,
) -> Result<(), QlFsmError> {
    let reply: HelloReply = deserialize_archived(archived_reply)?;
    let action = {
        let Some(entry) = fsm.peer.as_ref() else {
            return Ok(());
        };
        match &entry.session {
            ConnectionState::Initiator {
                hello,
                stage:
                    HandshakeInitiator::WaitingHelloReply {
                        initiator_secret, ..
                    },
                ..
            } => HelloReplyAction::Advance {
                hello: hello.clone(),
                initiator_secret: initiator_secret.clone(),
                responder_signing_key: entry.peer.signing_key.clone(),
            },
            ConnectionState::Initiator {
                stage:
                    HandshakeInitiator::WaitingReady {
                        reply: stored,
                        confirm,
                        ..
                    },
                ..
            } if same_reply(stored, &reply) => HelloReplyAction::ResendConfirm {
                confirm: confirm.clone(),
            },
            _ => return Ok(()),
        }
    };

    match action {
        HelloReplyAction::ResendConfirm { confirm } => {
            fsm.enqueue_handshake(
                header.sender,
                wire::handshake::HandshakeRecord::Confirm(confirm),
            );
        }
        HelloReplyAction::Advance {
            hello,
            initiator_secret,
            responder_signing_key,
        } => {
            let confirm_meta = fsm.next_control_meta(fsm.config.handshake_timeout);
            let (confirm, session_key) = match wire::handshake::build_confirm(
                &fsm.identity,
                header.sender,
                &responder_signing_key,
                &hello,
                archived_reply,
                &initiator_secret,
                confirm_meta,
            ) {
                Ok(result) => result,
                Err(_) => return Ok(()),
            };

            if fsm.is_replayed_control(header.sender, reply.meta) {
                return Ok(());
            }

            let deadline = fsm.state.now.instant + fsm.config.handshake_timeout;
            let retry_at = Some(fsm.state.now.instant + fsm.config.handshake_retry_interval);
            if let Some(entry) = fsm.peer.as_mut() {
                entry.session = ConnectionState::Initiator {
                    hello,
                    deadline,
                    stage: HandshakeInitiator::WaitingReady {
                        reply: reply.clone(),
                        confirm: confirm.clone(),
                        session_key,
                        retry_count: 0,
                        retry_at,
                    },
                };
            }
            fsm.enqueue_handshake(
                header.sender,
                wire::handshake::HandshakeRecord::Confirm(confirm),
            );
        }
    }

    Ok(())
}

fn deserialize_archived<T>(
    value: &impl rkyv::Deserialize<T, low::LowDeserializer<rkyv::rancor::Error>>,
) -> Result<T, QlFsmError> {
    low::deserialize::<T, rkyv::rancor::Error>(value).map_err(|_| QlFsmError::InvalidPayload)
}

pub fn handle_confirm(
    fsm: &mut QlFsm,
    header: &QlHeader,
    confirm: &wire::handshake::ArchivedConfirm,
    crypto: &impl QlCrypto,
) -> Result<(), QlFsmError> {
    if let Some(ready) = recent_ready_resend(fsm, header.sender, confirm) {
        fsm.enqueue_handshake(
            header.sender,
            wire::handshake::HandshakeRecord::Ready(ready),
        );
        return Ok(());
    }

    let outcome = {
        let Some(entry) = fsm.peer.as_ref() else {
            return Ok(());
        };
        let ConnectionState::Responder {
            hello,
            reply,
            deadline,
            stage: HandshakeResponder::WaitingConfirm { secrets, .. },
        } = &entry.session
        else {
            return Ok(());
        };

        wire::handshake::finalize_confirm(
            header.sender,
            fsm.identity.xid,
            &entry.peer.signing_key,
            hello,
            reply,
            confirm,
            secrets,
        )
        .map(|session_key| (hello.clone(), reply.clone(), *deadline, session_key))
    };

    let (hello, reply, deadline, session_key) = match outcome {
        Ok(result) => result,
        Err(_) => return Ok(()),
    };

    let meta: ControlMeta = (&confirm.meta).into();
    if fsm.is_replayed_control(header.sender, meta) {
        return Ok(());
    }

    let ready = wire::handshake::build_ready(
        QlHeader {
            sender: fsm.identity.xid,
            recipient: header.sender,
        },
        &session_key,
        fsm.next_control_meta(fsm.config.handshake_timeout),
        next_encrypted_nonce(crypto),
    );

    if let Some(entry) = fsm.peer.as_mut() {
        entry.session = ConnectionState::Connected {
            session_key,
            recent_ready: Some(RecentReady {
                hello,
                reply,
                ready: ready.clone(),
                expires_at: deadline,
            }),
        };
    }
    fsm.reset_session();

    fsm.enqueue_handshake(
        header.sender,
        wire::handshake::HandshakeRecord::Ready(ready),
    );
    fsm.emit_peer_status();
    Ok(())
}

pub fn handle_ready(
    fsm: &mut QlFsm,
    header: &QlHeader,
    ready: &mut wire::handshake::ArchivedReady,
) -> Result<(), QlFsmError> {
    let session_key = {
        let Some(entry) = fsm.peer.as_ref() else {
            return Ok(());
        };
        match &entry.session {
            ConnectionState::Initiator {
                stage: HandshakeInitiator::WaitingReady { session_key, .. },
                ..
            } => session_key.clone(),
            _ => return Ok(()),
        }
    };

    let body = match wire::handshake::decrypt_ready(header, ready, &session_key) {
        Ok(body) => body,
        Err(_) => return Ok(()),
    };
    if fsm.is_replayed_control(header.sender, body.meta) {
        return Ok(());
    }

    if let Some(entry) = fsm.peer.as_mut() {
        entry.session = ConnectionState::Connected {
            session_key,
            recent_ready: None,
        };
    }
    fsm.reset_session();
    fsm.emit_peer_status();
    Ok(())
}

pub fn handle_timer(fsm: &mut QlFsm) {
    let now = fsm.state.now.instant;
    if let Some(ConnectionState::Connected {
        recent_ready: Some(recent_ready),
        ..
    }) = fsm.peer.as_mut().map(|entry| &mut entry.session)
    {
        if recent_ready.expires_at <= now {
            if let Some(entry) = fsm.peer.as_mut() {
                if let ConnectionState::Connected { recent_ready, .. } = &mut entry.session {
                    *recent_ready = None;
                }
            }
        }
    }

    let mut retry_action = None;
    let mut disconnected = false;

    if let Some(entry) = fsm.peer.as_mut() {
        match &mut entry.session {
            ConnectionState::Initiator {
                hello,
                deadline,
                stage,
            } => {
                if *deadline <= now {
                    entry.session = ConnectionState::Disconnected;
                    disconnected = true;
                } else {
                    retry_action = handle_initiator_retry(
                        &entry.peer,
                        hello,
                        stage,
                        now,
                        fsm.config.handshake_retry_interval,
                        fsm.config.max_handshake_retries,
                    );
                    if retry_action.is_none() && initiator_retries_exhausted(stage) {
                        entry.session = ConnectionState::Disconnected;
                        disconnected = true;
                    }
                }
            }
            ConnectionState::Responder {
                reply,
                deadline,
                stage,
                ..
            } => {
                if *deadline <= now {
                    entry.session = ConnectionState::Disconnected;
                    disconnected = true;
                } else {
                    retry_action = handle_responder_retry(
                        &entry.peer,
                        reply,
                        stage,
                        now,
                        fsm.config.handshake_retry_interval,
                        fsm.config.max_handshake_retries,
                    );
                    if retry_action.is_none() && responder_retries_exhausted(stage) {
                        entry.session = ConnectionState::Disconnected;
                        disconnected = true;
                    }
                }
            }
            ConnectionState::Disconnected | ConnectionState::Connected { .. } => {}
        }
    }

    if disconnected {
        fsm.emit_peer_status();
    }

    if let Some(action) = retry_action {
        match action {
            RetryAction::Hello { peer, hello } => {
                fsm.enqueue_handshake(peer, wire::handshake::HandshakeRecord::Hello(hello));
            }
            RetryAction::HelloReply { peer, reply } => {
                fsm.enqueue_handshake(peer, wire::handshake::HandshakeRecord::HelloReply(reply));
            }
            RetryAction::Confirm { peer, confirm } => {
                fsm.enqueue_handshake(peer, wire::handshake::HandshakeRecord::Confirm(confirm));
            }
        }
    }
}

pub fn next_deadline(fsm: &QlFsm) -> Option<Instant> {
    let mut deadline = None;
    if let Some(entry) = fsm.peer.as_ref() {
        match &entry.session {
            ConnectionState::Initiator {
                deadline: session_deadline,
                stage,
                ..
            } => {
                deadline = Some(*session_deadline);
                deadline = min_optional(deadline, initiator_retry_at(stage));
            }
            ConnectionState::Responder {
                deadline: session_deadline,
                stage,
                ..
            } => {
                deadline = Some(*session_deadline);
                deadline = min_optional(deadline, responder_retry_at(stage));
            }
            ConnectionState::Connected {
                recent_ready: Some(recent_ready),
                ..
            } => {
                deadline = Some(recent_ready.expires_at);
            }
            ConnectionState::Disconnected | ConnectionState::Connected { .. } => {}
        }
    }
    deadline
}

fn start_initiator_handshake(fsm: &mut QlFsm, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
    let Some(entry) = fsm.peer.as_ref() else {
        return Err(QlFsmError::NoPeerBound);
    };
    if !matches!(entry.session, ConnectionState::Disconnected) {
        return Ok(());
    }

    let peer = entry.peer.clone();
    let meta = fsm.next_control_meta(fsm.config.handshake_timeout);
    let (hello, initiator_secret) = wire::handshake::build_hello(
        &fsm.identity,
        crypto,
        peer.xid,
        &peer.encapsulation_key,
        meta,
    )?;
    let deadline = fsm.state.now.instant + fsm.config.handshake_timeout;
    let retry_at = Some(fsm.state.now.instant + fsm.config.handshake_retry_interval);

    if let Some(entry) = fsm.peer.as_mut() {
        entry.session = ConnectionState::Initiator {
            hello: hello.clone(),
            deadline,
            stage: HandshakeInitiator::WaitingHelloReply {
                initiator_secret,
                retry_count: 0,
                retry_at,
            },
        };
    }

    fsm.enqueue_handshake(peer.xid, wire::handshake::HandshakeRecord::Hello(hello));
    fsm.emit_peer_status();
    Ok(())
}

fn recent_ready_resend(
    fsm: &QlFsm,
    peer: XID,
    confirm: &wire::handshake::ArchivedConfirm,
) -> Option<Ready> {
    let entry = fsm.peer.as_ref()?;
    let ConnectionState::Connected {
        recent_ready: Some(recent_ready),
        ..
    } = &entry.session
    else {
        return None;
    };
    if recent_ready.expires_at <= fsm.state.now.instant {
        return None;
    }
    wire::handshake::verify_confirm(
        peer,
        fsm.identity.xid,
        &entry.peer.signing_key,
        &recent_ready.hello,
        &recent_ready.reply,
        confirm,
    )
    .ok()?;
    Some(recent_ready.ready.clone())
}

fn handle_initiator_retry(
    peer: &Peer,
    hello: &Hello,
    stage: &mut HandshakeInitiator,
    now: Instant,
    retry_interval: std::time::Duration,
    max_retries: u8,
) -> Option<RetryAction> {
    match stage {
        HandshakeInitiator::WaitingHelloReply {
            retry_count,
            retry_at,
            ..
        } => {
            if retry_due(*retry_at, now) {
                if *retry_count >= max_retries {
                    *retry_at = None;
                    None
                } else {
                    *retry_count = retry_count.saturating_add(1);
                    *retry_at = Some(now + retry_interval);
                    Some(RetryAction::Hello {
                        peer: peer.xid,
                        hello: hello.clone(),
                    })
                }
            } else {
                None
            }
        }
        HandshakeInitiator::WaitingReady {
            confirm,
            retry_count,
            retry_at,
            ..
        } => {
            if retry_due(*retry_at, now) {
                if *retry_count >= max_retries {
                    *retry_at = None;
                    None
                } else {
                    *retry_count = retry_count.saturating_add(1);
                    *retry_at = Some(now + retry_interval);
                    Some(RetryAction::Confirm {
                        peer: peer.xid,
                        confirm: confirm.clone(),
                    })
                }
            } else {
                None
            }
        }
    }
}

fn handle_responder_retry(
    peer: &Peer,
    reply: &HelloReply,
    stage: &mut HandshakeResponder,
    now: Instant,
    retry_interval: std::time::Duration,
    max_retries: u8,
) -> Option<RetryAction> {
    match stage {
        HandshakeResponder::WaitingConfirm {
            retry_count,
            retry_at,
            ..
        } => {
            if retry_due(*retry_at, now) {
                if *retry_count >= max_retries {
                    *retry_at = None;
                    None
                } else {
                    *retry_count = retry_count.saturating_add(1);
                    *retry_at = Some(now + retry_interval);
                    Some(RetryAction::HelloReply {
                        peer: peer.xid,
                        reply: reply.clone(),
                    })
                }
            } else {
                None
            }
        }
    }
}

fn initiator_retries_exhausted(stage: &HandshakeInitiator) -> bool {
    match stage {
        HandshakeInitiator::WaitingHelloReply { retry_at, .. }
        | HandshakeInitiator::WaitingReady { retry_at, .. } => retry_at.is_none(),
    }
}

fn responder_retries_exhausted(stage: &HandshakeResponder) -> bool {
    match stage {
        HandshakeResponder::WaitingConfirm { retry_at, .. } => retry_at.is_none(),
    }
}

fn initiator_retry_at(stage: &HandshakeInitiator) -> Option<Instant> {
    match stage {
        HandshakeInitiator::WaitingHelloReply { retry_at, .. }
        | HandshakeInitiator::WaitingReady { retry_at, .. } => *retry_at,
    }
}

fn responder_retry_at(stage: &HandshakeResponder) -> Option<Instant> {
    match stage {
        HandshakeResponder::WaitingConfirm { retry_at, .. } => *retry_at,
    }
}

fn same_hello(stored: &Hello, incoming: &Hello) -> bool {
    stored.meta.control_id == incoming.meta.control_id && stored.nonce == incoming.nonce
}

fn same_reply(stored: &HelloReply, incoming: &HelloReply) -> bool {
    stored.meta.control_id == incoming.meta.control_id && stored.nonce == incoming.nonce
}

fn peer_hello_wins(
    local_hello: &Hello,
    local_sender: XID,
    peer_hello: &Hello,
    peer_sender: XID,
) -> bool {
    match peer_hello.nonce.0.cmp(&local_hello.nonce.0) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => peer_sender.0.cmp(&local_sender.0) == Ordering::Less,
    }
}

fn next_encrypted_nonce(crypto: &impl QlCrypto) -> wire::Nonce {
    let mut bytes = [0u8; wire::Nonce::NONCE_SIZE];
    crypto.fill_random_bytes(&mut bytes);
    wire::Nonce(bytes)
}

fn retry_due(retry_at: Option<Instant>, now: Instant) -> bool {
    retry_at.is_some_and(|deadline| deadline <= now)
}

fn min_optional(current: Option<Instant>, other: Option<Instant>) -> Option<Instant> {
    match (current, other) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}
