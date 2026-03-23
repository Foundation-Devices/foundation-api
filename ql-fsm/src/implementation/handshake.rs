use std::{cmp::Ordering, time::Instant};

use ql_wire::{
    self as wire, Confirm, ConfirmWire, EncryptedMessageWire, Hello, HelloReply, HelloReplyWire,
    HelloWire, MlDsaPublicKey, Nonce, QlCrypto, QlHeader, QlPayload, Ready, RefMut, SessionKey,
    XID,
};

use super::{
    emit_peer_status, enqueue_handshake, fail_pending_connect_session, is_replayed_control,
    next_control_meta,
};
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
        initiator_secret: SessionKey,
        responder_signing_key: MlDsaPublicKey,
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
    crypto: &impl QlCrypto,
    header: &QlHeader,
    hello: &RefMut<'_, HelloWire>,
) -> Result<(), QlFsmError> {
    let action = {
        let Some(entry) = fsm.peer.as_ref() else {
            return Ok(());
        };
        if wire::verify_hello(
            crypto,
            header.sender,
            fsm.identity.xid,
            &entry.peer.signing_key,
            hello,
            fsm.state.now.unix_secs,
        )
        .is_err()
        {
            return Ok(());
        }

        match &entry.session {
            ConnectionState::Initiator {
                hello: local_hello, ..
            } => {
                if peer_hello_wins_ref(local_hello, fsm.identity.xid, hello, header.sender) {
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
                if same_hello_ref(stored, hello) {
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
            enqueue_handshake(fsm, header.sender, QlPayload::HelloReply(reply));
        }
        HelloAction::StartResponder => {
            if is_replayed_control(fsm, header.sender, wire::ControlMeta::from_wire(hello.meta)) {
                return Ok(());
            }

            let peer = fsm.peer.as_ref().map(|entry| entry.peer.clone()).unwrap();
            let reply_meta = next_control_meta(fsm, fsm.config.handshake_timeout);
            let responder = wire::respond_hello(
                crypto,
                &fsm.identity,
                peer.xid,
                &peer.signing_key,
                &peer.encapsulation_key,
                hello,
                reply_meta,
                fsm.state.now.unix_secs,
            );

            let (reply, secrets) = match responder {
                Ok(result) => result,
                Err(_) => {
                    if let Some(entry) = fsm.peer.as_mut() {
                        entry.session = ConnectionState::Disconnected;
                    }
                    emit_peer_status(fsm);
                    return Ok(());
                }
            };

            let deadline = fsm.state.now.instant + fsm.config.handshake_timeout;
            let retry_at = Some(fsm.state.now.instant + fsm.config.handshake_retry_interval);
            if let Some(entry) = fsm.peer.as_mut() {
                entry.session = ConnectionState::Responder {
                    hello: wire::Hello::from_wire(hello),
                    reply: reply.clone(),
                    deadline,
                    stage: HandshakeResponder::WaitingConfirm {
                        secrets,
                        retry_count: 0,
                        retry_at,
                    },
                };
            }
            enqueue_handshake(fsm, header.sender, QlPayload::HelloReply(reply));
            emit_peer_status(fsm);
        }
    }

    Ok(())
}

pub fn handle_hello_reply(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    header: &QlHeader,
    reply: &RefMut<'_, HelloReplyWire>,
) -> Result<(), QlFsmError> {
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
                initiator_secret: *initiator_secret,
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
            } if same_reply_ref(stored, reply) => HelloReplyAction::ResendConfirm {
                confirm: confirm.clone(),
            },
            _ => return Ok(()),
        }
    };

    match action {
        HelloReplyAction::ResendConfirm { confirm } => {
            enqueue_handshake(fsm, header.sender, QlPayload::Confirm(confirm));
        }
        HelloReplyAction::Advance {
            hello,
            initiator_secret,
            responder_signing_key,
        } => {
            let confirm_meta = next_control_meta(fsm, fsm.config.handshake_timeout);
            let (confirm, session_key) = match wire::build_confirm(
                crypto,
                &fsm.identity,
                header.sender,
                &responder_signing_key,
                &hello,
                reply,
                &initiator_secret,
                confirm_meta,
                fsm.state.now.unix_secs,
            ) {
                Ok(result) => result,
                Err(_) => return Ok(()),
            };

            if is_replayed_control(fsm, header.sender, wire::ControlMeta::from_wire(reply.meta)) {
                return Ok(());
            }

            let deadline = fsm.state.now.instant + fsm.config.handshake_timeout;
            let retry_at = Some(fsm.state.now.instant + fsm.config.handshake_retry_interval);
            if let Some(entry) = fsm.peer.as_mut() {
                entry.session = ConnectionState::Initiator {
                    hello,
                    deadline,
                    stage: HandshakeInitiator::WaitingReady {
                        reply: wire::HelloReply::from_wire(reply),
                        confirm: confirm.clone(),
                        session_key,
                        retry_count: 0,
                        retry_at,
                    },
                };
            }
            enqueue_handshake(fsm, header.sender, QlPayload::Confirm(confirm));
        }
    }

    Ok(())
}

pub fn handle_confirm(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    header: &QlHeader,
    confirm: &RefMut<'_, ConfirmWire>,
) -> Result<(), QlFsmError> {
    if let Some(ready) = recent_ready_resend(fsm, crypto, header.sender, confirm) {
        enqueue_handshake(fsm, header.sender, QlPayload::Ready(ready));
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

        wire::finalize_confirm(
            crypto,
            header.sender,
            fsm.identity.xid,
            &entry.peer.signing_key,
            hello,
            reply,
            confirm,
            secrets,
            fsm.state.now.unix_secs,
        )
        .map(|session_key| (hello.clone(), reply.clone(), *deadline, session_key))
    };

    let (hello, reply, deadline, session_key) = match outcome {
        Ok(result) => result,
        Err(_) => return Ok(()),
    };

    if is_replayed_control(
        fsm,
        header.sender,
        wire::ControlMeta::from_wire(confirm.meta),
    ) {
        return Ok(());
    }

    let ready = wire::build_ready(
        crypto,
        QlHeader {
            sender: fsm.identity.xid,
            recipient: header.sender,
        },
        &session_key,
        next_control_meta(fsm, fsm.config.handshake_timeout),
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

    enqueue_handshake(fsm, header.sender, QlPayload::Ready(ready));
    emit_peer_status(fsm);
    Ok(())
}

pub fn handle_ready(
    fsm: &mut QlFsm,
    crypto: &impl QlCrypto,
    header: &QlHeader,
    ready: &mut RefMut<'_, EncryptedMessageWire>,
) -> Result<(), QlFsmError> {
    let session_key = {
        let Some(entry) = fsm.peer.as_ref() else {
            return Ok(());
        };
        match &entry.session {
            ConnectionState::Initiator {
                stage: HandshakeInitiator::WaitingReady { session_key, .. },
                ..
            } => *session_key,
            _ => return Ok(()),
        }
    };

    let body =
        match wire::decrypt_ready(crypto, header, ready, &session_key, fsm.state.now.unix_secs) {
            Ok(body) => body,
            Err(_) => return Ok(()),
        };
    if is_replayed_control(fsm, header.sender, body.meta) {
        return Ok(());
    }

    if let Some(entry) = fsm.peer.as_mut() {
        entry.session = ConnectionState::Connected {
            session_key,
            recent_ready: None,
        };
    }
    emit_peer_status(fsm);
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
        fail_pending_connect_session(fsm, ql_wire::CloseCode::TIMEOUT);
        emit_peer_status(fsm);
    }

    if let Some(action) = retry_action {
        match action {
            RetryAction::Hello { peer, hello } => {
                enqueue_handshake(fsm, peer, QlPayload::Hello(hello));
            }
            RetryAction::HelloReply { peer, reply } => {
                enqueue_handshake(fsm, peer, QlPayload::HelloReply(reply));
            }
            RetryAction::Confirm { peer, confirm } => {
                enqueue_handshake(fsm, peer, QlPayload::Confirm(confirm));
            }
        }
    }
}

pub fn next_handshake_deadline(fsm: &QlFsm) -> Option<Instant> {
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
    let meta = next_control_meta(fsm, fsm.config.handshake_timeout);
    let (hello, initiator_secret) = wire::build_hello(
        crypto,
        &fsm.identity,
        peer.xid,
        &peer.encapsulation_key,
        meta,
    );
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

    enqueue_handshake(fsm, peer.xid, QlPayload::Hello(hello));
    emit_peer_status(fsm);
    Ok(())
}

fn recent_ready_resend(
    fsm: &QlFsm,
    crypto: &impl QlCrypto,
    peer: XID,
    confirm: &RefMut<'_, ConfirmWire>,
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
    wire::verify_confirm(
        crypto,
        peer,
        fsm.identity.xid,
        &entry.peer.signing_key,
        &recent_ready.hello,
        &recent_ready.reply,
        confirm,
        fsm.state.now.unix_secs,
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

fn same_hello_ref(stored: &Hello, incoming: &RefMut<'_, HelloWire>) -> bool {
    stored.meta.control_id.0 == incoming.meta.control_id.get() && stored.nonce.0 == incoming.nonce
}

fn same_reply_ref(stored: &HelloReply, incoming: &RefMut<'_, HelloReplyWire>) -> bool {
    stored.meta.control_id.0 == incoming.meta.control_id.get() && stored.nonce.0 == incoming.nonce
}

fn peer_hello_wins_ref(
    local_hello: &Hello,
    local_sender: XID,
    peer_hello: &RefMut<'_, HelloWire>,
    peer_sender: XID,
) -> bool {
    match peer_hello.nonce.cmp(&local_hello.nonce.0) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => peer_sender.0.cmp(&local_sender.0) == Ordering::Less,
    }
}

fn next_encrypted_nonce(crypto: &impl QlCrypto) -> Nonce {
    let mut bytes = [0u8; Nonce::SIZE];
    crypto.fill_random_bytes(&mut bytes);
    Nonce(bytes)
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
