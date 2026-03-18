#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArenaKey {
    index: u32,
    generation: u32,
}

impl ArenaKey {
    fn index(self) -> usize {
        self.index as usize
    }
}

#[derive(Debug)]
struct Slot<T> {
    generation: u32,
    value: Option<T>,
    next_free: Option<u32>,
}

#[derive(Debug)]
pub struct GenerationalArena<T> {
    slots: Vec<Slot<T>>,
    free_head: Option<u32>,
    len: usize,
}

impl<T> GenerationalArena<T> {
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            free_head: None,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn contains(&self, key: ArenaKey) -> bool {
        self.get(key).is_some()
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.slots.iter().filter_map(|slot| slot.value.as_ref())
    }

    pub fn clear(&mut self) {
        self.slots.clear();
        self.free_head = None;
        self.len = 0;
    }

    pub fn insert(&mut self, value: T) -> ArenaKey {
        self.len += 1;

        if let Some(index) = self.free_head {
            let slot = &mut self.slots[index as usize];
            self.free_head = slot.next_free.take();
            slot.value = Some(value);
            return ArenaKey {
                index,
                generation: slot.generation,
            };
        }

        assert!(self.slots.len() < u32::MAX as usize);
        let index = self.slots.len() as u32;
        self.slots.push(Slot {
            generation: 0,
            value: Some(value),
            next_free: None,
        });
        ArenaKey {
            index,
            generation: 0,
        }
    }

    pub fn get(&self, key: ArenaKey) -> Option<&T> {
        let slot = self.slots.get(key.index())?;
        (slot.generation == key.generation)
            .then_some(slot.value.as_ref())
            .flatten()
    }

    pub fn get_mut(&mut self, key: ArenaKey) -> Option<&mut T> {
        let slot = self.slots.get_mut(key.index())?;
        (slot.generation == key.generation)
            .then_some(slot.value.as_mut())
            .flatten()
    }

    pub fn remove(&mut self, key: ArenaKey) -> Option<T> {
        let slot = self.slots.get_mut(key.index())?;
        if slot.generation != key.generation {
            return None;
        }

        let value = slot.value.take()?;
        slot.generation = slot.generation.wrapping_add(1);
        slot.next_free = self.free_head;
        self.free_head = Some(key.index);
        self.len -= 1;
        Some(value)
    }

    pub fn retain(&mut self, mut f: impl FnMut(ArenaKey, &mut T) -> bool) {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            let Some(value) = slot.value.as_mut() else {
                continue;
            };
            let key = ArenaKey {
                index: index as u32,
                generation: slot.generation,
            };
            if f(key, value) {
                continue;
            }
            let _ = slot.value.take();
            slot.generation = slot.generation.wrapping_add(1);
            slot.next_free = self.free_head;
            self.free_head = Some(index as u32);
            self.len -= 1;
        }
    }
}

impl<T> Default for GenerationalArena<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{ArenaKey, GenerationalArena};

    #[test]
    fn insert_get_remove_round_trips() {
        let mut arena = GenerationalArena::new();
        let key = arena.insert("hello");

        assert_eq!(arena.len(), 1);
        assert_eq!(arena.get(key), Some(&"hello"));
        assert!(arena.contains(key));

        assert_eq!(arena.remove(key), Some("hello"));
        assert!(arena.is_empty());
        assert_eq!(arena.get(key), None);
        assert!(!arena.contains(key));
    }

    #[test]
    fn stale_key_does_not_hit_reused_slot() {
        let mut arena = GenerationalArena::new();
        let old = arena.insert(10);
        assert_eq!(arena.remove(old), Some(10));

        let new = arena.insert(20);
        assert_eq!(old.index(), new.index());
        assert_ne!(old, new);

        assert_eq!(arena.get(old), None);
        assert_eq!(arena.get(new), Some(&20));
    }

    #[test]
    fn get_mut_updates_value() {
        let mut arena = GenerationalArena::new();
        let key = arena.insert(String::from("a"));

        arena.get_mut(key).unwrap().push('b');

        assert_eq!(arena.get(key).map(String::as_str), Some("ab"));
    }

    #[test]
    fn remove_rejects_wrong_generation() {
        let mut arena = GenerationalArena::new();
        let key = arena.insert(1u32);
        let wrong = ArenaKey {
            index: key.index as u32,
            generation: key.generation.wrapping_add(1),
        };

        assert_eq!(arena.remove(wrong), None);
        assert_eq!(arena.get(key), Some(&1));
    }
}
