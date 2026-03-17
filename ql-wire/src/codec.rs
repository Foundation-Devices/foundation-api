use std::cell::RefCell;

use rkyv::{
    api::low::{self, LowDeserializer, LowSerializer, LowValidator},
    bytecheck::CheckBytes,
    rancor,
    seal::Seal,
    ser::allocator::{Arena, ArenaHandle},
    Portable, Serialize,
};

use crate::WireError;

std::thread_local! {
    static ALLOC_ARENA: RefCell<Arena> = RefCell::new(Arena::new());
}

pub(crate) fn encode_value(
    value: &impl for<'a> Serialize<LowSerializer<Vec<u8>, ArenaHandle<'a>, rancor::Error>>,
) -> Vec<u8> {
    with_arena(|arena| {
        low::to_bytes_in_with_alloc::<_, _, rancor::Error>(value, Vec::new(), arena)
            .expect("wire serialization should not fail")
    })
}

pub(crate) fn access_value<T>(bytes: &[u8]) -> Result<&T, WireError>
where
    T: Portable + for<'a> CheckBytes<LowValidator<'a, rancor::Error>>,
{
    low::access::<T, rancor::Error>(bytes).map_err(|_| WireError::InvalidPayload)
}

pub(crate) fn access_mut_value<T>(bytes: &mut [u8]) -> Result<Seal<'_, T>, WireError>
where
    T: Portable + for<'a> CheckBytes<LowValidator<'a, rancor::Error>>,
{
    low::access_mut::<T, rancor::Error>(bytes).map_err(|_| WireError::InvalidPayload)
}

pub(crate) fn deserialize_value<T>(
    value: &impl rkyv::Deserialize<T, LowDeserializer<rancor::Error>>,
) -> Result<T, WireError> {
    low::deserialize::<T, rancor::Error>(value).map_err(|_| WireError::InvalidPayload)
}

fn with_arena<R>(f: impl FnOnce(ArenaHandle<'_>) -> R) -> R {
    ALLOC_ARENA.with(|arena| {
        let mut arena = arena.borrow_mut();
        f(arena.acquire())
    })
}
