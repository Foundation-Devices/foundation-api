use super::*;

fn handshake_bytes(
    sender: XID,
    recipient: XID,
    record: wire::handshake::HandshakeRecord,
) -> Vec<u8> {
    wire::encode_record(&QlRecord {
        header: QlHeader { sender, recipient },
        payload: QlPayload::Handshake(record),
    })
}

fn build_reply(
    initiator_identity: &QlIdentity,
    responder_identity: &QlIdentity,
    responder_crypto: &TestCrypto,
    hello: &wire::handshake::Hello,
    packet_id: u32,
) -> wire::handshake::HelloReply {
    let hello_bytes = wire::encode_value(hello);
    let hello_view = wire::access_value::<wire::handshake::ArchivedHello>(&hello_bytes).unwrap();
    let (reply, _secrets) = wire::handshake::respond_hello(
        responder_identity,
        responder_crypto,
        initiator_identity.xid,
        &initiator_identity.signing_public_key,
        &initiator_identity.encapsulation_public_key,
        hello_view,
        wire::ControlMeta {
            packet_id: PacketId(packet_id),
            valid_until: wire::now_secs().saturating_add(60),
        },
    )
    .unwrap();
    reply
}

fn build_confirm(
    initiator_identity: &QlIdentity,
    responder_identity: &QlIdentity,
    hello: &wire::handshake::Hello,
    reply: &wire::handshake::HelloReply,
    initiator_secret: &SymmetricKey,
    packet_id: u32,
) -> wire::handshake::Confirm {
    let reply_bytes = wire::encode_value(reply);
    let reply_view =
        wire::access_value::<wire::handshake::ArchivedHelloReply>(&reply_bytes).unwrap();
    let (confirm, _session_key) = wire::handshake::build_confirm(
        initiator_identity,
        responder_identity.xid,
        &responder_identity.signing_public_key,
        hello,
        reply_view,
        initiator_secret,
        wire::ControlMeta {
            packet_id: PacketId(packet_id),
            valid_until: wire::now_secs().saturating_add(60),
        },
    )
    .unwrap();
    confirm
}

fn pump_between(a: &mut EngineWrapper, b: &mut EngineWrapper, now: Instant) {
    loop {
        let mut progressed = false;

        while let Some(write) = a.take_next_write() {
            let bytes = write.bytes.clone();
            let _ = a.complete_write_collect(write.id, Ok(()));
            let _ = b.run_tick_collect(now, EngineInput::Incoming(bytes));
            progressed = true;
        }

        while let Some(write) = b.take_next_write() {
            let bytes = write.bytes.clone();
            let _ = b.complete_write_collect(write.id, Ok(()));
            let _ = a.run_tick_collect(now, EngineInput::Incoming(bytes));
            progressed = true;
        }

        if !progressed {
            break;
        }
    }
}

#[test]
fn handshake_deadline_is_derived_from_peer_state() {
    let mut config = EngineConfig::default();
    config.handshake_timeout = Duration::from_secs(5);
    config.handshake_retry_interval = Duration::ZERO;
    config.max_handshake_retries = 0;

    let identity = test_identity();
    let peer_identity = test_identity();
    let mut engine = EngineWrapper::new(
        Engine::new(
            config,
            identity.clone(),
            Some(peer_from_identity(&peer_identity)),
        ),
        TestCrypto::new(103),
    );
    let now = Instant::now();

    let _outputs = engine.run_tick_collect(now, EngineInput::Connect);
    assert_eq!(engine.next_deadline(), Some(now + Duration::from_secs(5)));

    let write = engine.take_next_write().unwrap();
    let _outputs = engine.complete_write_collect(write.id, Ok(()));
    assert_eq!(engine.next_deadline(), Some(now + Duration::from_secs(5)));

    let outputs = engine.run_tick_collect(now + Duration::from_secs(4), EngineInput::TimerExpired);
    assert!(!outputs.iter().any(|output| {
        matches!(
            output,
            EngineOutput::PeerStatusChanged {
                session: PeerSession::Disconnected,
                ..
            }
        )
    }));
    assert_eq!(engine.next_deadline(), Some(now + Duration::from_secs(5)));

    let outputs = engine.run_tick_collect(now + Duration::from_secs(5), EngineInput::TimerExpired);
    assert!(outputs.iter().any(|output| {
        matches!(
            output,
            EngineOutput::PeerStatusChanged {
                session: PeerSession::Disconnected,
                ..
            }
        )
    }));
}

#[test]
fn initiator_retries_hello_after_retry_interval() {
    let mut config = EngineConfig::default();
    config.handshake_timeout = Duration::from_secs(5);
    config.handshake_retry_interval = Duration::from_millis(250);
    config.max_handshake_retries = 2;

    let identity = test_identity();
    let peer_identity = test_identity();
    let mut engine = EngineWrapper::new(
        Engine::new(config, identity, Some(peer_from_identity(&peer_identity))),
        TestCrypto::new(111),
    );
    let now = Instant::now();

    let _ = engine.run_tick_collect(now, EngineInput::Connect);
    let hello_write = engine.take_next_write().unwrap();
    let hello_bytes = hello_write.bytes.clone();
    let _ = engine.complete_write_collect(hello_write.id, Ok(()));

    let _ = engine.run_tick_collect(now + Duration::from_millis(250), EngineInput::TimerExpired);
    let retry_write = engine.take_next_write().unwrap();
    assert_eq!(retry_write.bytes, hello_bytes);
    assert!(matches!(
        engine.peer.as_ref().map(|peer| &peer.session),
        Some(PeerSession::Initiator {
            stage: HandshakeInitiator::WaitingHelloReply { retry_count: 1, .. },
            ..
        })
    ));
}

#[test]
fn responder_retries_hello_reply_after_retry_interval() {
    let mut config = EngineConfig::default();
    config.handshake_timeout = Duration::from_secs(5);
    config.handshake_retry_interval = Duration::from_millis(250);
    config.max_handshake_retries = 2;

    let responder_identity = test_identity();
    let initiator_identity = test_identity();
    let initiator_crypto = TestCrypto::new(112);
    let responder_crypto = TestCrypto::new(113);
    let mut engine = EngineWrapper::new(
        Engine::new(
            config,
            responder_identity.clone(),
            Some(peer_from_identity(&initiator_identity)),
        ),
        responder_crypto,
    );
    let now = Instant::now();

    let (hello, _secret) = wire::handshake::build_hello(
        &initiator_identity,
        &initiator_crypto,
        responder_identity.xid,
        &responder_identity.encapsulation_public_key,
        wire::ControlMeta {
            packet_id: PacketId(81),
            valid_until: wire::now_secs().saturating_add(60),
        },
    )
    .unwrap();

    let _ = engine.run_tick_collect(
        now,
        EngineInput::Incoming(handshake_bytes(
            initiator_identity.xid,
            responder_identity.xid,
            wire::handshake::HandshakeRecord::Hello(hello),
        )),
    );
    let reply_write = engine.take_next_write().unwrap();
    let reply_bytes = reply_write.bytes.clone();
    let _ = engine.complete_write_collect(reply_write.id, Ok(()));

    let _ = engine.run_tick_collect(now + Duration::from_millis(250), EngineInput::TimerExpired);
    let retry_write = engine.take_next_write().unwrap();
    assert_eq!(retry_write.bytes, reply_bytes);
    assert!(matches!(
        engine.peer.as_ref().map(|peer| &peer.session),
        Some(PeerSession::Responder {
            stage: HandshakeResponder::WaitingConfirm { retry_count: 1, .. },
            ..
        })
    ));
}

#[test]
fn initiator_retries_confirm_after_retry_interval() {
    let mut config = EngineConfig::default();
    config.handshake_timeout = Duration::from_secs(5);
    config.handshake_retry_interval = Duration::from_millis(250);
    config.max_handshake_retries = 2;

    let identity = test_identity();
    let peer_identity = test_identity();
    let responder_crypto = TestCrypto::new(114);
    let mut engine = EngineWrapper::new(
        Engine::new(
            config,
            identity.clone(),
            Some(peer_from_identity(&peer_identity)),
        ),
        TestCrypto::new(115),
    );
    let now = Instant::now();

    let _ = engine.run_tick_collect(now, EngineInput::Connect);
    let hello_write = engine.take_next_write().unwrap();
    let hello_record = wire::decode_record(&hello_write.bytes).unwrap();
    let QlPayload::Handshake(wire::handshake::HandshakeRecord::Hello(hello)) = hello_record.payload
    else {
        panic!("expected hello record");
    };
    let _ = engine.complete_write_collect(hello_write.id, Ok(()));

    let reply = build_reply(&identity, &peer_identity, &responder_crypto, &hello, 82);
    let _ = engine.run_tick_collect(
        now,
        EngineInput::Incoming(handshake_bytes(
            peer_identity.xid,
            identity.xid,
            wire::handshake::HandshakeRecord::HelloReply(reply),
        )),
    );
    let confirm_write = engine.take_next_write().unwrap();
    let confirm_bytes = confirm_write.bytes.clone();
    let _ = engine.complete_write_collect(confirm_write.id, Ok(()));

    let _ = engine.run_tick_collect(now + Duration::from_millis(250), EngineInput::TimerExpired);
    let retry_write = engine.take_next_write().unwrap();
    assert_eq!(retry_write.bytes, confirm_bytes);
    assert!(matches!(
        engine.peer.as_ref().map(|peer| &peer.session),
        Some(PeerSession::Initiator {
            stage: HandshakeInitiator::WaitingReady { retry_count: 1, .. },
            ..
        })
    ));
}

#[test]
fn duplicate_hello_resends_hello_reply() {
    let responder_identity = test_identity();
    let initiator_identity = test_identity();
    let initiator_crypto = TestCrypto::new(116);
    let responder_crypto = TestCrypto::new(117);
    let mut engine = EngineWrapper::new(
        Engine::new(
            EngineConfig::default(),
            responder_identity.clone(),
            Some(peer_from_identity(&initiator_identity)),
        ),
        responder_crypto,
    );
    let now = Instant::now();

    let (hello, _secret) = wire::handshake::build_hello(
        &initiator_identity,
        &initiator_crypto,
        responder_identity.xid,
        &responder_identity.encapsulation_public_key,
        wire::ControlMeta {
            packet_id: PacketId(83),
            valid_until: wire::now_secs().saturating_add(60),
        },
    )
    .unwrap();
    let hello_bytes = handshake_bytes(
        initiator_identity.xid,
        responder_identity.xid,
        wire::handshake::HandshakeRecord::Hello(hello),
    );

    let _ = engine.run_tick_collect(now, EngineInput::Incoming(hello_bytes.clone()));
    let reply_write = engine.take_next_write().unwrap();
    let reply_bytes = reply_write.bytes.clone();
    let _ = engine.complete_write_collect(reply_write.id, Ok(()));

    let _ = engine.run_tick_collect(now, EngineInput::Incoming(hello_bytes));
    let resent_reply = engine.take_next_write().unwrap();
    assert_eq!(resent_reply.bytes, reply_bytes);
}

#[test]
fn duplicate_hello_reply_resends_confirm() {
    let identity = test_identity();
    let peer_identity = test_identity();
    let responder_crypto = TestCrypto::new(118);
    let mut engine = EngineWrapper::new(
        Engine::new(
            EngineConfig::default(),
            identity.clone(),
            Some(peer_from_identity(&peer_identity)),
        ),
        TestCrypto::new(119),
    );
    let now = Instant::now();

    let _ = engine.run_tick_collect(now, EngineInput::Connect);
    let hello_write = engine.take_next_write().unwrap();
    let hello_record = wire::decode_record(&hello_write.bytes).unwrap();
    let QlPayload::Handshake(wire::handshake::HandshakeRecord::Hello(hello)) = hello_record.payload
    else {
        panic!("expected hello record");
    };
    let _ = engine.complete_write_collect(hello_write.id, Ok(()));

    let reply = build_reply(&identity, &peer_identity, &responder_crypto, &hello, 84);
    let reply_bytes = handshake_bytes(
        peer_identity.xid,
        identity.xid,
        wire::handshake::HandshakeRecord::HelloReply(reply.clone()),
    );

    let _ = engine.run_tick_collect(now, EngineInput::Incoming(reply_bytes.clone()));
    let confirm_write = engine.take_next_write().unwrap();
    let confirm_bytes = confirm_write.bytes.clone();
    let _ = engine.complete_write_collect(confirm_write.id, Ok(()));

    let _ = engine.run_tick_collect(now, EngineInput::Incoming(reply_bytes));
    let resent_confirm = engine.take_next_write().unwrap();
    assert_eq!(resent_confirm.bytes, confirm_bytes);
}

#[test]
fn responder_resends_ready_for_duplicate_confirm_after_connecting() {
    let responder_identity = test_identity();
    let initiator_identity = test_identity();
    let initiator_crypto = TestCrypto::new(120);
    let responder_crypto = TestCrypto::new(121);
    let mut engine = EngineWrapper::new(
        Engine::new(
            EngineConfig::default(),
            responder_identity.clone(),
            Some(peer_from_identity(&initiator_identity)),
        ),
        responder_crypto,
    );
    let now = Instant::now();

    let (hello, initiator_secret) = wire::handshake::build_hello(
        &initiator_identity,
        &initiator_crypto,
        responder_identity.xid,
        &responder_identity.encapsulation_public_key,
        wire::ControlMeta {
            packet_id: PacketId(85),
            valid_until: wire::now_secs().saturating_add(60),
        },
    )
    .unwrap();
    let _ = engine.run_tick_collect(
        now,
        EngineInput::Incoming(handshake_bytes(
            initiator_identity.xid,
            responder_identity.xid,
            wire::handshake::HandshakeRecord::Hello(hello.clone()),
        )),
    );

    let reply_write = engine.take_next_write().unwrap();
    let reply_record = wire::decode_record(&reply_write.bytes).unwrap();
    let QlPayload::Handshake(wire::handshake::HandshakeRecord::HelloReply(reply)) =
        reply_record.payload
    else {
        panic!("expected hello reply");
    };
    let _ = engine.complete_write_collect(reply_write.id, Ok(()));

    let confirm = build_confirm(
        &initiator_identity,
        &responder_identity,
        &hello,
        &reply,
        &initiator_secret,
        86,
    );
    let confirm_bytes = handshake_bytes(
        initiator_identity.xid,
        responder_identity.xid,
        wire::handshake::HandshakeRecord::Confirm(confirm.clone()),
    );

    let _ = engine.run_tick_collect(now, EngineInput::Incoming(confirm_bytes.clone()));
    let ready_write = engine.take_next_write().unwrap();
    let ready_bytes = ready_write.bytes.clone();
    let _ = engine.complete_write_collect(ready_write.id, Ok(()));

    assert!(matches!(
        engine.peer.as_ref().map(|peer| &peer.session),
        Some(PeerSession::Connected {
            recent_ready: Some(_),
            ..
        })
    ));

    let _ = engine.run_tick_collect(now, EngineInput::Incoming(confirm_bytes));
    let resent_ready = engine.take_next_write().unwrap();
    assert_eq!(resent_ready.bytes, ready_bytes);
}

#[test]
fn stale_hello_reply_does_not_abort_fresh_handshake() {
    let identity = test_identity();
    let peer_identity = test_identity();
    let responder_crypto = TestCrypto::new(122);
    let stale_initiator_crypto = TestCrypto::new(123);
    let mut engine = EngineWrapper::new(
        Engine::new(
            EngineConfig::default(),
            identity.clone(),
            Some(peer_from_identity(&peer_identity)),
        ),
        TestCrypto::new(124),
    );
    let now = Instant::now();

    let (stale_hello, _stale_secret) = wire::handshake::build_hello(
        &identity,
        &stale_initiator_crypto,
        peer_identity.xid,
        &peer_identity.encapsulation_public_key,
        wire::ControlMeta {
            packet_id: PacketId(87),
            valid_until: wire::now_secs().saturating_add(60),
        },
    )
    .unwrap();
    let stale_reply = build_reply(
        &identity,
        &peer_identity,
        &responder_crypto,
        &stale_hello,
        88,
    );

    let _ = engine.run_tick_collect(now, EngineInput::Connect);
    let hello_write = engine.take_next_write().unwrap();
    let hello_record = wire::decode_record(&hello_write.bytes).unwrap();
    let QlPayload::Handshake(wire::handshake::HandshakeRecord::Hello(current_hello)) =
        hello_record.payload
    else {
        panic!("expected hello record");
    };
    let _ = engine.complete_write_collect(hello_write.id, Ok(()));

    let outputs = engine.run_tick_collect(
        now,
        EngineInput::Incoming(handshake_bytes(
            peer_identity.xid,
            identity.xid,
            wire::handshake::HandshakeRecord::HelloReply(stale_reply),
        )),
    );
    assert!(!outputs.iter().any(|output| matches!(
        output,
        EngineOutput::PeerStatusChanged {
            session: PeerSession::Disconnected,
            ..
        }
    )));
    assert!(matches!(
        engine.peer.as_ref().map(|peer| &peer.session),
        Some(PeerSession::Initiator {
            stage: HandshakeInitiator::WaitingHelloReply { .. },
            ..
        })
    ));

    let current_reply = build_reply(
        &identity,
        &peer_identity,
        &responder_crypto,
        &current_hello,
        89,
    );
    let _ = engine.run_tick_collect(
        now,
        EngineInput::Incoming(handshake_bytes(
            peer_identity.xid,
            identity.xid,
            wire::handshake::HandshakeRecord::HelloReply(current_reply),
        )),
    );
    assert!(matches!(
        engine.peer.as_ref().map(|peer| &peer.session),
        Some(PeerSession::Initiator {
            stage: HandshakeInitiator::WaitingReady { .. },
            ..
        })
    ));
    assert!(engine.take_next_write().is_some());
}

#[test]
fn stale_confirm_does_not_abort_fresh_handshake() {
    let responder_identity = test_identity();
    let initiator_identity = test_identity();
    let responder_crypto = TestCrypto::new(125);
    let initiator_crypto = TestCrypto::new(126);
    let stale_initiator_crypto = TestCrypto::new(127);
    let mut engine = EngineWrapper::new(
        Engine::new(
            EngineConfig::default(),
            responder_identity.clone(),
            Some(peer_from_identity(&initiator_identity)),
        ),
        responder_crypto,
    );
    let now = Instant::now();

    let (stale_hello, stale_secret) = wire::handshake::build_hello(
        &initiator_identity,
        &stale_initiator_crypto,
        responder_identity.xid,
        &responder_identity.encapsulation_public_key,
        wire::ControlMeta {
            packet_id: PacketId(90),
            valid_until: wire::now_secs().saturating_add(60),
        },
    )
    .unwrap();
    let stale_reply = build_reply(
        &initiator_identity,
        &responder_identity,
        &TestCrypto::new(128),
        &stale_hello,
        91,
    );
    let stale_confirm = build_confirm(
        &initiator_identity,
        &responder_identity,
        &stale_hello,
        &stale_reply,
        &stale_secret,
        92,
    );

    let (hello, initiator_secret) = wire::handshake::build_hello(
        &initiator_identity,
        &initiator_crypto,
        responder_identity.xid,
        &responder_identity.encapsulation_public_key,
        wire::ControlMeta {
            packet_id: PacketId(93),
            valid_until: wire::now_secs().saturating_add(60),
        },
    )
    .unwrap();
    let _ = engine.run_tick_collect(
        now,
        EngineInput::Incoming(handshake_bytes(
            initiator_identity.xid,
            responder_identity.xid,
            wire::handshake::HandshakeRecord::Hello(hello.clone()),
        )),
    );

    let reply_write = engine.take_next_write().unwrap();
    let reply_record = wire::decode_record(&reply_write.bytes).unwrap();
    let QlPayload::Handshake(wire::handshake::HandshakeRecord::HelloReply(reply)) =
        reply_record.payload
    else {
        panic!("expected hello reply");
    };
    let _ = engine.complete_write_collect(reply_write.id, Ok(()));

    let outputs = engine.run_tick_collect(
        now,
        EngineInput::Incoming(handshake_bytes(
            initiator_identity.xid,
            responder_identity.xid,
            wire::handshake::HandshakeRecord::Confirm(stale_confirm),
        )),
    );
    assert!(!outputs.iter().any(|output| matches!(
        output,
        EngineOutput::PeerStatusChanged {
            session: PeerSession::Disconnected,
            ..
        }
    )));
    assert!(matches!(
        engine.peer.as_ref().map(|peer| &peer.session),
        Some(PeerSession::Responder {
            stage: HandshakeResponder::WaitingConfirm { .. },
            ..
        })
    ));

    let confirm = build_confirm(
        &initiator_identity,
        &responder_identity,
        &hello,
        &reply,
        &initiator_secret,
        94,
    );
    let _ = engine.run_tick_collect(
        now,
        EngineInput::Incoming(handshake_bytes(
            initiator_identity.xid,
            responder_identity.xid,
            wire::handshake::HandshakeRecord::Confirm(confirm),
        )),
    );
    assert!(engine.take_next_write().is_some());
}

#[test]
fn initiator_waits_for_ready_before_connecting() {
    let config = EngineConfig::default();
    let identity = test_identity();
    let peer_identity = test_identity();
    let responder_crypto = TestCrypto::new(129);
    let mut engine = EngineWrapper::new(
        Engine::new(
            config,
            identity.clone(),
            Some(peer_from_identity(&peer_identity)),
        ),
        TestCrypto::new(130),
    );
    let now = Instant::now();

    let _outputs = engine.run_tick_collect(now, EngineInput::Connect);

    let hello_write = engine.take_next_write().unwrap();
    let hello_record = wire::decode_record(&hello_write.bytes).unwrap();
    let QlPayload::Handshake(wire::handshake::HandshakeRecord::Hello(hello)) = hello_record.payload
    else {
        panic!("expected hello record");
    };
    let _outputs = engine.complete_write_collect(hello_write.id, Ok(()));

    let reply = build_reply(&identity, &peer_identity, &responder_crypto, &hello, 95);
    let _outputs = engine.run_tick_collect(
        now,
        EngineInput::Incoming(handshake_bytes(
            peer_identity.xid,
            identity.xid,
            wire::handshake::HandshakeRecord::HelloReply(reply),
        )),
    );

    let confirm_write = engine.take_next_write().unwrap();
    let _outputs = engine.complete_write_collect(confirm_write.id, Ok(()));

    assert!(matches!(
        engine.peer.as_ref().map(|peer| &peer.session),
        Some(PeerSession::Initiator {
            stage: HandshakeInitiator::WaitingReady { .. },
            ..
        })
    ));
    assert!(matches!(
        engine.open_stream(now, Vec::new(), None, StreamConfig::default()),
        Err(QlError::MissingSession)
    ));

    let pending_session_key = match engine.peer.as_ref().map(|peer| &peer.session) {
        Some(PeerSession::Initiator { session_key, .. }) => session_key.clone(),
        other => panic!("expected pending initiator session, got {other:?}"),
    };
    let outputs = engine.run_tick_collect(
        now,
        EngineInput::Incoming(handshake_bytes(
            peer_identity.xid,
            identity.xid,
            wire::handshake::HandshakeRecord::Ready(wire::handshake::build_ready(
                QlHeader {
                    sender: peer_identity.xid,
                    recipient: identity.xid,
                },
                &pending_session_key,
                wire::ControlMeta {
                    packet_id: PacketId(96),
                    valid_until: wire::now_secs().saturating_add(60),
                },
                [9; wire::encrypted_message::NONCE_SIZE],
            )),
        )),
    );

    assert!(matches!(
        engine.peer.as_ref().map(|peer| &peer.session),
        Some(PeerSession::Connected { .. })
    ));
    assert!(outputs.iter().any(|output| matches!(
        output,
        EngineOutput::PeerStatusChanged {
            session: PeerSession::Connected { .. },
            ..
        }
    )));
}

#[test]
fn handshake_retry_limit_disconnects_initiator() {
    let mut config = EngineConfig::default();
    config.handshake_timeout = Duration::from_secs(5);
    config.handshake_retry_interval = Duration::from_millis(250);
    config.max_handshake_retries = 1;

    let identity = test_identity();
    let peer_identity = test_identity();
    let mut engine = EngineWrapper::new(
        Engine::new(config, identity, Some(peer_from_identity(&peer_identity))),
        TestCrypto::new(131),
    );
    let now = Instant::now();

    let _ = engine.run_tick_collect(now, EngineInput::Connect);
    let hello_write = engine.take_next_write().unwrap();
    let hello_bytes = hello_write.bytes.clone();
    let _ = engine.complete_write_collect(hello_write.id, Ok(()));

    let _ = engine.run_tick_collect(now + Duration::from_millis(250), EngineInput::TimerExpired);
    let retry_write = engine.take_next_write().unwrap();
    assert_eq!(retry_write.bytes, hello_bytes);
    let _ = engine.complete_write_collect(retry_write.id, Ok(()));

    let outputs =
        engine.run_tick_collect(now + Duration::from_millis(500), EngineInput::TimerExpired);
    assert!(outputs.iter().any(|output| matches!(
        output,
        EngineOutput::PeerStatusChanged {
            session: PeerSession::Disconnected,
            ..
        }
    )));
    assert!(matches!(
        engine.peer.as_ref().map(|peer| &peer.session),
        Some(PeerSession::Disconnected)
    ));
}

#[test]
fn simultaneous_connect_converges_to_connected_peers() {
    let config = EngineConfig::default();
    let identity_a = test_identity();
    let identity_b = test_identity();
    let mut a = EngineWrapper::new(
        Engine::new(
            config,
            identity_a.clone(),
            Some(peer_from_identity(&identity_b)),
        ),
        TestCrypto::new(132),
    );
    let mut b = EngineWrapper::new(
        Engine::new(
            config,
            identity_b.clone(),
            Some(peer_from_identity(&identity_a)),
        ),
        TestCrypto::new(133),
    );
    let now = Instant::now();

    let _ = a.run_tick_collect(now, EngineInput::Connect);
    let _ = b.run_tick_collect(now, EngineInput::Connect);

    let hello_a = a.take_next_write().unwrap();
    let hello_a_bytes = hello_a.bytes.clone();
    let _ = a.complete_write_collect(hello_a.id, Ok(()));

    let hello_b = b.take_next_write().unwrap();
    let hello_b_bytes = hello_b.bytes.clone();
    let _ = b.complete_write_collect(hello_b.id, Ok(()));

    let _ = a.run_tick_collect(now, EngineInput::Incoming(hello_b_bytes));
    let _ = b.run_tick_collect(now, EngineInput::Incoming(hello_a_bytes));

    pump_between(&mut a, &mut b, now);

    assert!(matches!(
        a.peer.as_ref().map(|peer| &peer.session),
        Some(PeerSession::Connected { .. })
    ));
    assert!(matches!(
        b.peer.as_ref().map(|peer| &peer.session),
        Some(PeerSession::Connected { .. })
    ));
}
