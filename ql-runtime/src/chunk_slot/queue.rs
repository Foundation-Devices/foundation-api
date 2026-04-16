//! local single-slot queue for `chunk_slot` to avoid `ConcurrentQueue<Bytes>` taking 512 bytes instead of 40
//! copied from `concurrent_queue::single::Single<T>` in `concurrent-queue`

use core::mem::MaybeUninit;

use super::sync::*;

const LOCKED: usize = 1 << 0;
const PUSHED: usize = 1 << 1;
const CLOSED: usize = 1 << 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopError {
    Empty,
    Closed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PushError<T> {
    Full(T),
    Closed(T),
}

/// A single-element queue.
pub struct Single<T> {
    state: AtomicUsize,
    slot: UnsafeCell<MaybeUninit<T>>,
}

unsafe impl<T> Send for Single<T> {}
unsafe impl<T> Sync for Single<T> {}

impl<T> Single<T> {
    /// Creates a new single-element queue.
    pub fn new() -> Single<T> {
        Single {
            state: AtomicUsize::new(0),
            slot: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Attempts to push an item into the queue.
    pub fn push(&self, value: T) -> Result<(), PushError<T>> {
        // Lock and fill the slot.
        let state = self
            .state
            .compare_exchange(0, LOCKED | PUSHED, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap_or_else(|x| x);

        if state == 0 {
            // Write the value and unlock.
            self.slot.with_mut(|slot| unsafe {
                slot.write(MaybeUninit::new(value));
            });
            self.state.fetch_and(!LOCKED, Ordering::Release);
            Ok(())
        } else if state & CLOSED != 0 {
            Err(PushError::Closed(value))
        } else {
            Err(PushError::Full(value))
        }
    }

    /// Attempts to pop an item from the queue.
    pub fn pop(&self) -> Result<T, PopError> {
        let mut state = PUSHED;
        loop {
            // Lock and empty the slot.
            let prev = self
                .state
                .compare_exchange(
                    state,
                    (state | LOCKED) & !PUSHED,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .unwrap_or_else(|x| x);

            if prev == state {
                // Read the value and unlock.
                let value = self
                    .slot
                    .with_mut(|slot| unsafe { slot.read().assume_init() });
                self.state.fetch_and(!LOCKED, Ordering::Release);
                return Ok(value);
            }

            if prev & PUSHED == 0 {
                if prev & CLOSED == 0 {
                    return Err(PopError::Empty);
                } else {
                    return Err(PopError::Closed);
                }
            }

            if prev & LOCKED == 0 {
                state = prev;
            } else {
                busy_wait();
                state = prev & !LOCKED;
            }
        }
    }

    /// Returns the number of items in the queue.
    pub fn len(&self) -> usize {
        usize::from(self.state.load(Ordering::SeqCst) & PUSHED != 0)
    }

    /// Returns `true` if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Closes the queue.
    ///
    /// Returns `true` if this call closed the queue.
    pub fn close(&self) -> bool {
        let state = self.state.fetch_or(CLOSED, Ordering::SeqCst);
        state & CLOSED == 0
    }

    /// Returns `true` if the queue is closed.
    pub fn is_closed(&self) -> bool {
        self.state.load(Ordering::SeqCst) & CLOSED != 0
    }
}

impl<T> Drop for Single<T> {
    fn drop(&mut self) {
        // Drop the value in the slot.
        let Self { state, slot } = self;
        state.with_mut(|state| {
            if *state & PUSHED != 0 {
                slot.with_mut(|slot| unsafe {
                    let value = &mut *slot;
                    value.as_mut_ptr().drop_in_place();
                });
            }
        });
    }
}
