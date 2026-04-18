//! local single-slot queue for stream io
//! copied from `concurrent_queue::single::Single<T>` in `concurrent-queue`

use core::mem::MaybeUninit;

#[allow(clippy::wildcard_imports)]
use super::sync::*;

const LOCKED: usize = 1 << 0;
const PUSHED: usize = 1 << 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PopError;

#[derive(Debug, PartialEq, Eq)]
pub enum PushError<T> {
    Full(T),
    Closed(T),
}

/// A single-element queue.
pub struct Slot<T> {
    state: AtomicUsize,
    value: UnsafeCell<MaybeUninit<T>>,
}

unsafe impl<T: Send> Send for Slot<T> {}
unsafe impl<T: Send> Sync for Slot<T> {}

impl<T> Slot<T> {
    /// Creates a new single-element queue.
    pub fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    #[inline]
    pub fn load_state(&self) -> usize {
        self.state.load(Ordering::Acquire)
    }

    #[inline]
    pub fn fetch_or(&self, bits: usize) -> usize {
        self.state.fetch_or(bits, Ordering::Release)
    }

    #[inline]
    pub fn compare_exchange(&self, current: usize, new: usize) -> Result<(), usize> {
        self.state
            .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
    }

    /// Attempts to push an item into the queue.
    pub fn try_push(&self, value: T, closed_mask: usize) -> Result<(), PushError<T>> {
        let mut state = self.load_state();
        loop {
            if state & closed_mask != 0 {
                return Err(PushError::Closed(value));
            }
            if state & LOCKED != 0 {
                busy_wait();
                state = self.load_state();
                continue;
            }
            if state & PUSHED != 0 {
                return Err(PushError::Full(value));
            }

            // Lock and fill the slot.
            let new_state = state | LOCKED | PUSHED;
            match self.compare_exchange(state, new_state) {
                Ok(()) => {
                    // Write the value and unlock.
                    self.value.with_mut(|slot| unsafe {
                        slot.write(MaybeUninit::new(value));
                    });
                    self.state.fetch_and(!LOCKED, Ordering::Release);
                    return Ok(());
                }
                Err(actual) => state = actual,
            }
        }
    }

    /// Attempts to push an item into the queue, displacing another if necessary.
    pub fn force_push(&self, value: T) -> Option<T> {
        // Attempt to lock the slot.
        let mut state = self.load_state();

        loop {
            if state & LOCKED != 0 {
                busy_wait();
                state = self.load_state();
                continue;
            }

            // Lock the slot.
            let new_state = state | LOCKED | PUSHED;
            match self.compare_exchange(state, new_state) {
                Ok(()) => {
                    // If the value was pushed, swap out the value.
                    let displaced = if state & PUSHED == 0 {
                        // SAFETY: write is safe because we have locked the state.
                        self.value.with_mut(|slot| unsafe {
                            slot.write(MaybeUninit::new(value));
                        });
                        None
                    } else {
                        // SAFETY: replace is safe because we have locked the state, and
                        // assume_init is safe because we have checked that the value was pushed.
                        self.value.with_mut(move |slot| unsafe {
                            Some(std::ptr::replace(slot, MaybeUninit::new(value)).assume_init())
                        })
                    };

                    // We can unlock the slot now.
                    self.state.fetch_and(!LOCKED, Ordering::Release);
                    return displaced;
                }
                Err(actual) => state = actual,
            }
        }
    }

    /// Attempts to pop an item from the queue.
    pub fn pop(&self) -> Result<T, PopError> {
        let mut state = PUSHED;
        loop {
            if state & LOCKED != 0 {
                busy_wait();
                state = self.load_state();
                continue;
            }
            if state & PUSHED == 0 {
                return Err(PopError);
            }

            // Lock and empty the slot.
            let new_state = (state | LOCKED) & !PUSHED;
            match self.compare_exchange(state, new_state) {
                Ok(()) => {
                    // Read the value and unlock.
                    let value = self
                        .value
                        .with_mut(|slot| unsafe { slot.read().assume_init() });
                    self.state.fetch_and(!LOCKED, Ordering::Release);
                    return Ok(value);
                }
                Err(actual) => state = actual,
            }
        }
    }

    #[inline]
    pub fn is_empty_state(state: usize) -> bool {
        state & PUSHED == 0
    }

}

impl<T> Drop for Slot<T> {
    fn drop(&mut self) {
        // Drop the value in the slot.
        self.state.with_mut(|state| {
            if *state & PUSHED != 0 {
                self.value.with_mut(|slot| unsafe {
                    let value = &mut *slot;
                    value.as_mut_ptr().drop_in_place();
                });
            }
        });
    }
}
