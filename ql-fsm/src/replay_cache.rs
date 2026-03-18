use std::collections::{hash_map::Entry, HashMap};

use ql_wire::{ControlId, ControlMeta, XID};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ReplayKey {
    peer: XID,
    control_id: ControlId,
}

#[derive(Debug, Default)]
pub struct ReplayCache {
    valid_until_by_key: HashMap<ReplayKey, u64>,
}

impl ReplayCache {
    pub fn check_and_store_valid_until(
        &mut self,
        peer: XID,
        meta: ControlMeta,
        now_secs: u64,
    ) -> bool {
        self.valid_until_by_key
            .retain(|_, valid_until| *valid_until > now_secs);

        let key = ReplayKey {
            peer,
            control_id: meta.control_id,
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
