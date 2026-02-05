use std::{
    cmp::Reverse,
    collections::{binary_heap::PeekMut, BinaryHeap, HashSet},
};

use bc_components::XID;

use crate::{runtime::internal::now_secs, MessageId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReplayNamespace {
    Peer,
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReplayKey {
    pub peer: XID,
    pub namespace: ReplayNamespace,
    pub message_id: MessageId,
}

impl ReplayKey {
    pub const fn new(peer: XID, namespace: ReplayNamespace, message_id: MessageId) -> Self {
        Self {
            peer,
            namespace,
            message_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExpiryEntry {
    expires_at: u64,
    key: ReplayKey,
}

impl Ord for ExpiryEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.expires_at
            .cmp(&other.expires_at)
            .then_with(|| self.key.cmp(&other.key))
    }
}

impl PartialOrd for ExpiryEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Default)]
pub struct ReplayCache {
    entries: HashSet<ReplayKey>,
    expirations: BinaryHeap<Reverse<ExpiryEntry>>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self {
            entries: HashSet::new(),
            expirations: BinaryHeap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn add(&mut self, key: ReplayKey, expires_at: u64) {
        if self.entries.insert(key) {
            self.expirations
                .push(Reverse(ExpiryEntry { expires_at, key }));
        }
    }

    pub fn check_and_store(&mut self, key: ReplayKey, expires_at: u64) -> bool {
        let now_secs = now_secs();
        self.check_and_store_at(key, expires_at, now_secs)
    }

    pub fn check_and_store_valid_until(&mut self, key: ReplayKey, valid_until: u64) -> bool {
        let now_secs = now_secs();
        self.check_and_store_at(key, valid_until, now_secs)
    }

    pub fn purge_expired(&mut self) {
        let now_secs = now_secs();
        self.purge_expired_at(now_secs);
    }

    pub fn clear_peer(&mut self, peer: XID) {
        self.entries.retain(|entry| entry.peer != peer);
        self.expirations.retain(|entry| entry.0.key.peer != peer);
    }

    fn check_and_store_at(&mut self, key: ReplayKey, expires_at: u64, now_secs: u64) -> bool {
        self.purge_expired_at(now_secs);
        if self.entries.contains(&key) {
            return true;
        }
        self.entries.insert(key);
        self.expirations
            .push(Reverse(ExpiryEntry { expires_at, key }));
        false
    }

    fn purge_expired_at(&mut self, now_secs: u64) {
        while let Some(entry) = self.expirations.peek_mut() {
            if entry.0.expires_at > now_secs {
                break;
            }
            let entry = PeekMut::pop(entry).0;
            self.entries.remove(&entry.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_with_byte(byte: u8) -> XID {
        XID::from_data([byte; XID::XID_SIZE])
    }

    #[test]
    fn check_and_store_detects_replay() {
        let mut cache = ReplayCache::new();
        let peer = peer_with_byte(1);
        let key = ReplayKey::new(peer, ReplayNamespace::Peer, MessageId::new(1));
        let now_secs = 100;
        let expires_at = 110;

        assert!(!cache.check_and_store_at(key, expires_at, now_secs));
        assert!(cache.check_and_store_at(key, expires_at, now_secs));
    }

    #[test]
    fn purge_expired_removes_old_entries() {
        let mut cache = ReplayCache::new();
        let now_secs = 100;
        let expired_at = 99;
        let future_at = 110;

        let key_old = ReplayKey::new(peer_with_byte(2), ReplayNamespace::Peer, MessageId::new(2));
        let key_new = ReplayKey::new(peer_with_byte(3), ReplayNamespace::Peer, MessageId::new(3));

        cache.add(key_old, expired_at);
        cache.add(key_new, future_at);

        cache.purge_expired_at(now_secs);
        assert_eq!(cache.len(), 1);
        assert!(!cache.check_and_store_at(key_old, future_at, now_secs));
    }

    #[test]
    fn clear_peer_removes_peer_entries() {
        let mut cache = ReplayCache::new();
        let now_secs = 100;
        let expires_at = 110;

        let peer_a = peer_with_byte(4);
        let peer_b = peer_with_byte(5);
        let key_a = ReplayKey::new(peer_a, ReplayNamespace::Peer, MessageId::new(4));
        let key_b = ReplayKey::new(peer_b, ReplayNamespace::Peer, MessageId::new(5));

        cache.add(key_a, expires_at);
        cache.add(key_b, expires_at);

        cache.clear_peer(peer_a);
        assert_eq!(cache.len(), 1);
        assert!(!cache.check_and_store_at(key_a, expires_at, now_secs));
    }
}
