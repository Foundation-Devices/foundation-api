pub mod handshake;
pub mod peer;

use std::time::Duration;

use ql_wire::{
    self as wire, handshake::ArchivedHandshakeRecord, ArchivedQlPayload, ControlId, ControlMeta,
    Nonce, QlCrypto, QlHeader, QlPayload, QlRecord, XID,
};
use rkyv::api::low;

use crate::{
    session::{SessionEvent, SessionFsmConfig, StreamIncoming, StreamNamespace},
    Peer, QlFsm, QlFsmError, QlFsmEvent, QlSessionEvent,
};

impl QlFsm {
    pub fn bind_peer_inner(&mut self, peer: Peer) {
        peer::handle_bind_peer(self, peer);
    }

    pub fn pair_inner(&mut self, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
        peer::handle_pair_local(self, crypto)
    }

    pub fn connect_inner(&mut self, crypto: &impl QlCrypto) -> Result<(), QlFsmError> {
        handshake::handle_connect(self, crypto)
    }

    pub fn receive_inner(
        &mut self,
        mut bytes: Vec<u8>,
        crypto: &impl QlCrypto,
    ) -> Result<(), QlFsmError> {
        let archived = wire::access_record_mut(&mut bytes)?;
        let archived = unsafe { archived.unseal_unchecked() };
        let header: QlHeader = deserialize_archived(&archived.header)?;

        if header.recipient != self.identity.xid {
            return Ok(());
        }
        if !matches!(&archived.payload, ArchivedQlPayload::Pair(_)) {
            let Some(peer) = self.peer.as_ref().map(|entry| entry.peer.xid) else {
                return Ok(());
            };
            if header.sender != peer {
                return Ok(());
            }
        }

        match &mut archived.payload {
            ArchivedQlPayload::Pair(request) => {
                peer::handle_pair(self, &header, request, crypto)?;
            }
            ArchivedQlPayload::Handshake(ArchivedHandshakeRecord::Hello(archived_hello)) => {
                handshake::handle_hello(self, &header, archived_hello, crypto)?;
            }
            ArchivedQlPayload::Handshake(ArchivedHandshakeRecord::HelloReply(archived_reply)) => {
                handshake::handle_hello_reply(self, &header, archived_reply)?;
            }
            ArchivedQlPayload::Handshake(ArchivedHandshakeRecord::Confirm(archived_confirm)) => {
                handshake::handle_confirm(self, &header, archived_confirm, crypto)?;
            }
            ArchivedQlPayload::Handshake(ArchivedHandshakeRecord::Ready(archived_ready)) => {
                handshake::handle_ready(self, &header, archived_ready)?;
            }
            ArchivedQlPayload::Encrypted(encrypted) => {
                let Some((_, session_key)) = self.peer_session() else {
                    return Ok(());
                };
                let envelope =
                    match wire::encrypted::decrypt_record(&header, encrypted, &session_key) {
                        Ok(envelope) => envelope,
                        Err(_) => return Ok(()),
                    };
                self.session.receive(self.state.now.instant, envelope);
                self.drain_session_events();
            }
        }

        Ok(())
    }

    pub fn on_timer_inner(&mut self) {
        handshake::handle_timer(self);
        if self.peer_session().is_some() {
            self.session.on_timer(self.state.now.instant);
            self.drain_session_events();
        }
    }

    pub fn next_deadline_inner(&self) -> Option<std::time::Instant> {
        [
            handshake::next_deadline(self),
            self.peer_session()
                .map(|_| self.session.next_deadline())
                .flatten(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub fn take_next_outbound_inner(&mut self, crypto: &impl QlCrypto) -> Option<QlRecord> {
        if let Some(record) = self.state.outbound.pop_front() {
            return Some(record);
        }

        if matches!(
            self.peer.as_ref().map(|entry| &entry.session),
            Some(crate::state::ConnectionState::Disconnected)
        ) && self.session.has_pending_stream_work()
        {
            let _ = self.connect_inner(crypto);
            if let Some(record) = self.state.outbound.pop_front() {
                return Some(record);
            }
        }

        let (recipient, session_key) = self.peer_session()?;
        let envelope = self.session.next_outbound(self.state.now.instant)?;
        let mut nonce = [0u8; Nonce::NONCE_SIZE];
        crypto.fill_random_bytes(&mut nonce);
        Some(wire::encrypted::encrypt_record(
            QlHeader {
                sender: self.identity.xid,
                recipient,
            },
            &session_key,
            &envelope,
            Nonce(nonce),
        ))
    }

    pub fn take_next_event_inner(&mut self) -> Option<QlFsmEvent> {
        self.state.events.pop_front()
    }

    fn emit_peer_status(&mut self) {
        if let Some(entry) = self.peer.as_ref() {
            self.state.events.push_back(QlFsmEvent::PeerStatusChanged {
                peer: entry.peer.xid,
                status: entry.session.status(),
            });
        }
    }

    fn next_control_meta(&mut self, lifetime: Duration) -> ControlMeta {
        let control_id = ControlId(self.state.next_control_id);
        self.state.next_control_id = self.state.next_control_id.wrapping_add(1);
        ControlMeta {
            control_id,
            valid_until: deadline_after_secs(self.state.now.unix_secs, lifetime),
        }
    }

    fn enqueue_handshake(&mut self, peer: XID, record: wire::handshake::HandshakeRecord) {
        self.state.outbound.push_back(QlRecord {
            header: QlHeader {
                sender: self.identity.xid,
                recipient: peer,
            },
            payload: QlPayload::Handshake(record),
        });
    }

    fn is_replayed_control(&mut self, peer: XID, meta: ControlMeta) -> bool {
        self.state
            .replay_cache
            .check_and_store_valid_until(peer, meta, self.state.now.unix_secs)
    }

    fn peer_session(&self) -> Option<(XID, bc_components::SymmetricKey)> {
        let entry = self.peer.as_ref()?;
        let session_key = entry.session.session_key()?.clone();
        Some((entry.peer.xid, session_key))
    }

    fn reset_session(&mut self) {
        let local_namespace = self
            .peer
            .as_ref()
            .map(|peer| StreamNamespace::for_local(self.identity.xid, peer.peer.xid))
            .unwrap_or(StreamNamespace::Low);
        self.session = crate::session::SessionFsm::new(
            SessionFsmConfig {
                local_namespace,
                ack_delay: self.config.session_ack_delay,
                retransmit_timeout: self.config.session_retransmit_timeout,
                keepalive_interval: self.config.session_keepalive_interval,
                peer_timeout: self.config.session_peer_timeout,
            },
            self.state.now.instant,
        );
    }

    fn fail_pending_connect_session(&mut self, code: ql_wire::CloseCode) {
        if !self.session.has_pending_stream_work() {
            return;
        }
        self.reset_session();
        self.state
            .session_events
            .push_back(QlSessionEvent::SessionClosed(ql_wire::SessionCloseBody {
                code,
            }));
    }

    fn drain_session_events(&mut self) {
        while let Some(event) = self.session.take_next_event() {
            match event {
                SessionEvent::Opened(stream_id) => {
                    self.state
                        .session_events
                        .push_back(QlSessionEvent::Opened(stream_id));
                }
                SessionEvent::Readable(stream_id) => {
                    while let Some(incoming) = self.session.take_next_inbound(stream_id) {
                        match incoming {
                            StreamIncoming::Data(bytes) => {
                                self.state
                                    .session_events
                                    .push_back(QlSessionEvent::Data { stream_id, bytes });
                            }
                            StreamIncoming::Finished => {
                                self.state
                                    .session_events
                                    .push_back(QlSessionEvent::Finished(stream_id));
                            }
                            StreamIncoming::Closed(frame) => {
                                self.state
                                    .session_events
                                    .push_back(QlSessionEvent::Closed(frame));
                            }
                        }
                    }
                }
                SessionEvent::WritableClosed(stream_id) => {
                    self.state
                        .session_events
                        .push_back(QlSessionEvent::WritableClosed(stream_id));
                }
                SessionEvent::Unpaired => {
                    self.state
                        .session_events
                        .push_back(QlSessionEvent::Unpaired);
                    self.peer = None;
                    self.reset_session();
                    self.state.events.push_back(QlFsmEvent::ClearPeer);
                }
                SessionEvent::SessionClosed(close) => {
                    self.state
                        .session_events
                        .push_back(QlSessionEvent::SessionClosed(close.clone()));
                    if let Some(entry) = self.peer.as_mut() {
                        if matches!(
                            entry.session,
                            crate::state::ConnectionState::Connected { .. }
                        ) {
                            entry.session = crate::state::ConnectionState::Disconnected;
                            self.emit_peer_status();
                        }
                    }
                    self.reset_session();
                }
            }
        }
    }
}

fn deadline_after_secs(now_secs: u64, duration: Duration) -> u64 {
    now_secs.saturating_add(duration_to_secs(duration))
}

fn duration_to_secs(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
}

fn deserialize_archived<T>(
    value: &impl rkyv::Deserialize<T, low::LowDeserializer<rkyv::rancor::Error>>,
) -> Result<T, QlFsmError> {
    low::deserialize::<T, rkyv::rancor::Error>(value).map_err(|_| QlFsmError::InvalidPayload)
}
