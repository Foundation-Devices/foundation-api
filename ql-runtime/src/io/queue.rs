//! local single-slot queue for stream io
//! copied from `concurrent_queue::single::Single<T>` in `concurrent-queue`

use core::mem::MaybeUninit;

#[allow(clippy::wildcard_imports)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct ForcePushError<T>(pub T);

/// A single-element queue.
pub struct Single<T> {
    state: AtomicUsize,
    slot: UnsafeCell<MaybeUninit<T>>,
}

#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl<T> Send for Single<T> {}
unsafe impl<T> Sync for Single<T> {}

impl<T> Single<T> {
    /// Creates a new single-element queue.
    pub fn new() -> Self {
        Self {
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

    /// Attempts to push an item into the queue, displacing another if necessary.
    pub fn force_push(&self, value: T) -> Result<Option<T>, ForcePushError<T>> {
        // Attempt to lock the slot.
        let mut state = 0;

        loop {
            // Lock the slot.
            let prev = self
                .state
                .compare_exchange(state, LOCKED | PUSHED, Ordering::SeqCst, Ordering::SeqCst)
                .unwrap_or_else(|x| x);

            if prev & CLOSED != 0 {
                return Err(ForcePushError(value));
            }

            if prev == state {
                // If the value was pushed, swap out the value.
                let prev_value = if prev & PUSHED == 0 {
                    // SAFETY: write is safe because we have locked the state.
                    self.slot.with_mut(|slot| unsafe {
                        slot.write(MaybeUninit::new(value));
                    });
                    None
                } else {
                    // SAFETY: replace is safe because we have locked the state, and
                    // assume_init is safe because we have checked that the value was pushed.
                    self.slot.with_mut(move |slot| unsafe {
                        Some(std::ptr::replace(slot, MaybeUninit::new(value)).assume_init())
                    })
                };

                if let Some(prev_value) = prev_value {
                    // We can unlock the slot now.
                    self.state.fetch_and(!LOCKED, Ordering::Release);
                    // Return the old value.
                    return Ok(Some(prev_value));
                }

                // We can unlock the slot now.
                self.state.fetch_and(!LOCKED, Ordering::Release);
                return Ok(None);
            }

            // Try to go for the current (pushed) state.
            if prev & LOCKED == 0 {
                state = prev;
            } else {
                // State is locked.
                busy_wait();
                state = prev & !LOCKED;
            }
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
                return if prev & CLOSED == 0 {
                    Err(PopError::Empty)
                } else {
                    Err(PopError::Closed)
                };
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
