#[cfg(not(all(test, loom)))]
mod inner {
    pub use std::{
        cell::UnsafeCell,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    pub fn busy_wait() {
        std::thread::yield_now();
    }

    pub trait UnsafeCellExt {
        type Value;

        fn with_mut<R, F>(&self, f: F) -> R
        where
            F: FnOnce(*mut Self::Value) -> R;
    }

    impl<T> UnsafeCellExt for UnsafeCell<T> {
        type Value = T;

        fn with_mut<R, F>(&self, f: F) -> R
        where
            F: FnOnce(*mut Self::Value) -> R,
        {
            f(self.get())
        }
    }

    pub trait AtomicExt {
        type Value;

        fn with_mut<R, F>(&mut self, f: F) -> R
        where
            F: FnOnce(&mut Self::Value) -> R;
    }

    impl AtomicExt for AtomicUsize {
        type Value = usize;

        fn with_mut<R, F>(&mut self, f: F) -> R
        where
            F: FnOnce(&mut Self::Value) -> R,
        {
            f(self.get_mut())
        }
    }
}

#[cfg(all(test, loom))]
mod inner {
    pub use loom::{
        cell::UnsafeCell,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        thread::yield_now as busy_wait,
    };
}

pub use inner::*;
