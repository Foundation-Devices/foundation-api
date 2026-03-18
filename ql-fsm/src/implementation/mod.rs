pub mod handshake;
pub mod peer;

use std::time::Duration;

use ql_wire::{
    self as wire, handshake::ArchivedHandshakeRecord, ArchivedQlPayload, ControlId, ControlMeta,
    QlCrypto, QlHeader, QlPayload, QlRecord, XID,
};
use rkyv::api::low;

use crate::{Peer, QlFsm, QlFsmError, QlFsmEvent};

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
            ArchivedQlPayload::Encrypted(_) => {}
        }

        Ok(())
    }

    pub fn on_timer_inner(&mut self) {
        handshake::handle_timer(self);
    }

    pub fn next_deadline_inner(&self) -> Option<std::time::Instant> {
        handshake::next_deadline(self)
    }

    pub fn take_next_outbound_inner(&mut self) -> Option<QlRecord> {
        self.state.outbound.pop_front()
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
