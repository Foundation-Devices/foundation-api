use std::collections::{hash_map::Entry, HashMap};

use ql_wire::{HandshakeId, HandshakeMeta, XID};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ReplayKey {
    peer: XID,
    handshake_id: HandshakeId,
}

#[derive(Debug, Default)]
pub struct ReplayCache {
    valid_until_by_key: HashMap<ReplayKey, u64>,
}

impl ReplayCache {
    pub fn check_and_store_valid_until(
        &mut self,
        peer: XID,
        meta: HandshakeMeta,
        now_secs: u64,
    ) -> bool {
        self.valid_until_by_key
            .retain(|_, stored_valid_until| *stored_valid_until > now_secs);

        let key = ReplayKey {
            peer,
            handshake_id: meta.handshake_id,
        };

        match self.valid_until_by_key.entry(key) {
            Entry::Occupied(_) => true,
            Entry::Vacant(entry) => {
                entry.insert(meta.valid_until);
                false
            }
        }
    }
}
