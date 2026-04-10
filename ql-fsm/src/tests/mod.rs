mod handshake;
mod proptest;
mod session;

use std::time::{Duration, Instant};

use ql_wire::{
    self, test_identities, test_identity, ConnectionId, PairingToken, QlCrypto, SessionKey,
    SoftwareCrypto, TransportParams,
};

use crate::{
    session::{SessionConfig, SessionFsm, StreamParity},
    state::{ConnectedState, LinkState, SessionTransport},
    Event, FsmTime, NoPeerError, OutboundWrite, QlFsm, QlFsmConfig, WriteId,
};

type TestCrypto = SoftwareCrypto;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    A,
    B,
}

impl Side {
    fn idx(self) -> usize {
        match self {
            Side::A => 0,
            Side::B => 1,
        }
    }
}

struct Node {
    fsm: QlFsm,
    crypto: TestCrypto,
}

struct Harness {
    now: Instant,
    unix_secs: u64,
    a: Node,
    b: Node,
}

struct DecodedSessionWrite {
    record: Vec<u8>,
    write_id: Option<WriteId>,
    header: ql_wire::SessionHeader,
    frames: Vec<ql_wire::SessionFrame<Vec<u8>>>,
}

impl Harness {
    fn paired_known(config: QlFsmConfig) -> Self {
        Self::paired_with_configs(config, config, true, true)
    }

    fn paired(config: QlFsmConfig, know_a: bool, know_b: bool) -> Self {
        Self::paired_with_configs(config, config, know_a, know_b)
    }

    fn paired_known_with_configs(config_a: QlFsmConfig, config_b: QlFsmConfig) -> Self {
        Self::paired_with_configs(config_a, config_b, true, true)
    }

    fn paired_with_configs(
        config_a: QlFsmConfig,
        config_b: QlFsmConfig,
        know_a: bool,
        know_b: bool,
    ) -> Self {
        let (identity_a, identity_b) = test_identities(&SoftwareCrypto);
        let now = Instant::now();
        let time = FsmTime {
            instant: now,
            unix_secs: 1_700_000_000,
        };

        let mut harness = Self {
            now,
            unix_secs: time.unix_secs,
            a: Node {
                fsm: QlFsm::new(config_a, identity_a.clone(), time),
                crypto: SoftwareCrypto,
            },
            b: Node {
                fsm: QlFsm::new(config_b, identity_b.clone(), time),
                crypto: SoftwareCrypto,
            },
        };

        if know_a {
            harness.a.fsm.bind_peer(identity_b.bundle());
        }
        if know_b {
            harness.b.fsm.bind_peer(identity_a.bundle());
        }

        harness
    }

    fn connected(config: QlFsmConfig) -> Self {
        let mut harness = Self::paired_known(config);
        let a_to_b_key = SessionKey::from_data([7; SessionKey::SIZE]);
        let b_to_a_key = SessionKey::from_data([9; SessionKey::SIZE]);
        let a_to_b_conn = ConnectionId::from_data([0xA1; ConnectionId::SIZE]);
        let b_to_a_conn = ConnectionId::from_data([0xB2; ConnectionId::SIZE]);

        harness.a.fsm.state.link = LinkState::Connected(ConnectedState {
            transport: SessionTransport {
                tx_key: a_to_b_key.clone(),
                rx_key: b_to_a_key.clone(),
                tx_connection_id: a_to_b_conn,
                rx_connection_id: b_to_a_conn,
                remote_transport_params: TransportParams {
                    initial_stream_receive_window: harness
                        .b
                        .fsm
                        .config
                        .session_stream_receive_buffer_size,
                },
            },
            session: SessionFsm::new(session_config(&harness, true), harness.now),
        });
        harness.b.fsm.state.link = LinkState::Connected(ConnectedState {
            transport: SessionTransport {
                tx_key: b_to_a_key,
                rx_key: a_to_b_key,
                tx_connection_id: b_to_a_conn,
                rx_connection_id: a_to_b_conn,
                remote_transport_params: TransportParams {
                    initial_stream_receive_window: harness
                        .a
                        .fsm
                        .config
                        .session_stream_receive_buffer_size,
                },
            },
            session: SessionFsm::new(session_config(&harness, false), harness.now),
        });
        harness
    }

    fn time(&self) -> FsmTime {
        FsmTime {
            instant: self.now,
            unix_secs: self.unix_secs,
        }
    }

    fn advance(&mut self, duration: Duration) {
        self.now += duration;
        self.unix_secs = self.unix_secs.saturating_add(duration.as_secs());
    }

    fn node(&self, side: Side) -> &Node {
        match side {
            Side::A => &self.a,
            Side::B => &self.b,
        }
    }

    fn node_mut(&mut self, side: Side) -> &mut Node {
        match side {
            Side::A => &mut self.a,
            Side::B => &mut self.b,
        }
    }

    fn next_outbound(&mut self, side: Side) -> Option<Vec<u8>> {
        let write = self.next_write(side)?;
        if let Some(id) = write.session_write_id {
            self.confirm_write(side, id);
        }
        Some(write.record)
    }

    fn next_write(&mut self, side: Side) -> Option<OutboundWrite> {
        let time = self.time();
        let Node { fsm, crypto } = self.node_mut(side);
        fsm.take_next_write(time, crypto)
    }

    fn next_decoded_outbound(&mut self, side: Side) -> Option<DecodedSessionWrite> {
        let write = self.next_write(side)?;
        if let Some(id) = write.session_write_id {
            self.confirm_write(side, id);
        }
        Some(self.decode_session_write(write, side))
    }

    fn next_decoded_write(&mut self, side: Side) -> Option<DecodedSessionWrite> {
        let write = self.next_write(side)?;
        Some(self.decode_session_write(write, side))
    }

    fn connect_ik(&mut self, side: Side) -> Result<(), NoPeerError> {
        let time = self.time();
        let Node { fsm, crypto } = self.node_mut(side);
        fsm.connect_ik(time, crypto)
    }

    fn connect_kk(&mut self, side: Side) -> Result<(), NoPeerError> {
        let time = self.time();
        let Node { fsm, crypto } = self.node_mut(side);
        fsm.connect_kk(time, crypto)
    }

    fn connect_xx(&mut self, side: Side, token: PairingToken) {
        let time = self.time();
        let Node { fsm, crypto } = self.node_mut(side);
        fsm.connect_xx(time, token, crypto);
    }

    fn deliver(&mut self, side: Side, record: Vec<u8>) {
        let time = self.time();
        let Node { fsm, crypto } = self.node_mut(side);
        fsm.receive(time, record, crypto).unwrap();
    }

    fn confirm_write(&mut self, side: Side, write_id: WriteId) {
        let time = self.time();
        self.node_mut(side)
            .fsm
            .confirm_session_write(time, write_id);
    }

    fn reject_write(&mut self, side: Side, write_id: WriteId) {
        let time = self.time();
        self.node_mut(side).fsm.reject_session_write(time, write_id);
    }

    fn decode_session_write(&self, write: OutboundWrite, side: Side) -> DecodedSessionWrite {
        let peer = self.node(match side {
            Side::A => Side::B,
            Side::B => Side::A,
        });
        let crypto = &peer.crypto;
        let session_key = &peer.fsm.state.link.transport().unwrap().rx_key;
        let (header, frames) = decrypt_record(crypto, &write.record, session_key);
        DecodedSessionWrite {
            record: write.record,
            write_id: write.session_write_id,
            header,
            frames,
        }
    }

    fn on_timer(&mut self, side: Side) {
        let time = self.time();
        self.node_mut(side).fsm.on_timer(time);
    }

    fn take_event(&mut self, side: Side) -> Option<Event> {
        self.node_mut(side).fsm.poll_event()
    }

    fn drain_events(&mut self, side: Side) -> Vec<Event> {
        let mut events = Vec::new();
        while let Some(event) = self.take_event(side) {
            events.push(event);
        }
        events
    }

    fn pump(&mut self) {
        for _ in 0..128 {
            let mut progressed = false;

            while let Some(record) = self.next_outbound(Side::A) {
                progressed = true;
                self.deliver(Side::B, record);
            }

            while let Some(record) = self.next_outbound(Side::B) {
                progressed = true;
                self.deliver(Side::A, record);
            }

            if !progressed {
                return;
            }
        }

        panic!("pump did not quiesce");
    }
}

fn pairing_token(byte: u8) -> PairingToken {
    PairingToken([byte; PairingToken::SIZE])
}

fn session_config(harness: &Harness, a: bool) -> SessionConfig {
    let (local, peer, config) = if a {
        (
            harness.a.fsm.identity.xid,
            harness.a.fsm.state.peer.as_ref().unwrap().xid,
            harness.a.fsm.config,
        )
    } else {
        (
            harness.b.fsm.identity.xid,
            harness.b.fsm.state.peer.as_ref().unwrap().xid,
            harness.b.fsm.config,
        )
    };

    SessionConfig {
        local_parity: StreamParity::for_local(local, peer),
        record_max_size: config.session_record_max_size,
        ack_delay: config.session_record_ack_delay,
        retransmit_timeout: config.session_record_retransmit_timeout,
        keepalive_interval: config.session_keepalive_interval,
        peer_timeout: config.session_peer_timeout,
        stream_send_buffer_size: config.session_stream_send_buffer_size,
        stream_receive_buffer_size: config.session_stream_receive_buffer_size,
        initial_peer_stream_receive_window: if a {
            harness.b.fsm.config.session_stream_receive_buffer_size
        } else {
            harness.a.fsm.config.session_stream_receive_buffer_size
        },
    }
}

fn decrypt_record(
    crypto: &impl QlCrypto,
    record: &[u8],
    session_key: &SessionKey,
) -> (ql_wire::SessionHeader, Vec<ql_wire::SessionFrame<Vec<u8>>>) {
    let (_header, record) =
        ql_wire::decode_record::<ql_wire::QlSessionRecord<_>, _>(record).unwrap();
    let plaintext = ql_wire::decrypt_record(
        crypto,
        &record.header,
        record.payload.into_owned(),
        session_key,
    )
    .unwrap();
    (
        record.header,
        ql_wire::decode_session_frames(&plaintext).unwrap(),
    )
}
