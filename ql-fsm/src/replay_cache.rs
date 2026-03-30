use std::collections::{hash_map::Entry, HashMap};

use ql_wire::{HandshakeId, HandshakeMeta};

#[derive(Debug, Default)]
pub struct ReplayCache {
    valid_until_by_id: HashMap<HandshakeId, u64>,
}

impl ReplayCache {
    pub fn check_and_store_valid_until(&mut self, meta: HandshakeMeta, now_secs: u64) -> bool {
        self.valid_until_by_id
            .retain(|_, stored_valid_until| *stored_valid_until > now_secs);

        match self.valid_until_by_id.entry(meta.handshake_id) {
            Entry::Occupied(_) => true,
            Entry::Vacant(entry) => {
                entry.insert(meta.valid_until);
                false
            }
        }
    }
}
