//! per-stream shared io state
//! each lane has one slot and one waker
//! the low slot bits belong to `slot.rs` and the higher bits here carry lane-specific flags

use std::task::Waker;

use bytes::Bytes;
use diatomic_waker::DiatomicWaker;
use ql_wire::StreamId;

use super::{
    slot::{PopError, PushError, Slot},
    sync::Arc,
};
use crate::QlStreamError;

pub(super) fn new(stream_id: StreamId) -> Arc<Inner> {
    Arc::new(Inner {
        stream_id,
        rx: RxInner::new(),
        tx: TxInner::new(),
    })
}

pub(super) struct Inner {
    pub(super) stream_id: StreamId,
    pub(super) rx: RxInner,
    pub(super) tx: TxInner,
}

pub enum Item {
    Chunk(Bytes),
    Error(QlStreamError),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ForcePushError<T>(pub T);

/// reader-lane shared state
pub struct RxInner {
    slot: Slot<Item>,
    changed: DiatomicWaker,
}

impl RxInner {
    const FINISHED: usize = 1 << 2;

    fn new() -> Self {
        Self {
            slot: Slot::new(),
            changed: DiatomicWaker::new(),
        }
    }

    pub fn try_write(&self, bytes: Bytes) -> Result<(), PushError<Bytes>> {
        try_write_chunk(&self.slot, &self.changed, bytes, Self::FINISHED)
    }

    /// marks clean reader eof
    pub fn finish(&self) {
        if self.slot.fetch_or(Self::FINISHED) & Self::FINISHED == 0 {
            self.changed.notify();
        }
    }

    /// stores a terminal reader error
    pub fn fail(
        &self,
        error: QlStreamError,
    ) -> Option<Bytes> {
        let displaced = self.slot.force_push(Item::Error(error));
        self.changed.notify();
        displaced_bytes(displaced)
    }

    pub fn load_state(&self) -> usize {
        self.slot.load_state()
    }

    pub fn is_finished(state: usize) -> bool {
        state & Self::FINISHED != 0
    }

    pub fn pop(&self) -> Result<Item, PopError> {
        pop_item(&self.slot, &self.changed)
    }

    /// registers the sole reader-lane waiter
    pub fn register_waiter(&self, waker: &Waker) {
        // Safety: StreamReader is the only reader-lane registrar for this
        // shared state, so register/unregister never run concurrently.
        unsafe { self.changed.register(waker) };
    }

    /// unregisters the sole reader-lane waiter
    pub fn unregister_waiter(&self) {
        // Safety: StreamReader is the only reader-lane registrar for this
        // shared state, so register/unregister never run concurrently.
        unsafe { self.changed.unregister() };
    }
}

/// writer-lane shared state
///
/// finish and fail race to establish the terminal result
/// terminal errors are stored in the slot
pub struct TxInner {
    slot: Slot<Item>,
    changed: DiatomicWaker,
}

impl TxInner {
    const FINISH_REQUESTED: usize = 1 << 2;
    const TERMINAL_READY: usize = 1 << 3;
    const TERMINAL_OK: usize = 1 << 4;

    fn new() -> Self {
        Self {
            slot: Slot::new(),
            changed: DiatomicWaker::new(),
        }
    }

    pub fn load_state(&self) -> usize {
        self.slot.load_state()
    }

    pub fn finish_requested(state: usize) -> bool {
        state & Self::FINISH_REQUESTED != 0
    }

    pub fn terminal_ready(state: usize) -> bool {
        state & Self::TERMINAL_READY != 0
    }

    pub fn terminal_ok(state: usize) -> bool {
        state & Self::TERMINAL_OK != 0
    }

    pub fn try_write(&self, bytes: Bytes) -> Result<(), PushError<Bytes>> {
        try_write_chunk(
            &self.slot,
            &self.changed,
            bytes,
            Self::FINISH_REQUESTED | Self::TERMINAL_READY,
        )
    }

    /// prevents future chunk writes once observed
    pub fn request_finish(&self) {
        if self.slot.fetch_or(Self::FINISH_REQUESTED) & Self::FINISH_REQUESTED == 0 {
            self.changed.notify();
        }
    }

    /// commits a clean writer eof
    pub fn finish(&self) {
        let mut state = self.slot.load_state();
        loop {
            if Self::terminal_ready(state) {
                return;
            }

            let new_state = state | Self::TERMINAL_READY | Self::TERMINAL_OK;
            match self.slot.compare_exchange(state, new_state) {
                Ok(()) => {
                    self.changed.notify();
                    return;
                }
                Err(actual) => state = actual,
            }
        }
    }

    /// stores a terminal writer error
    /// futures calls will have no effect
    pub fn fail(
        &self,
        error: QlStreamError,
    ) -> Result<Option<Bytes>, ForcePushError<QlStreamError>> {
        let mut state = self.slot.load_state();
        loop {
            if Self::terminal_ready(state) {
                return Err(ForcePushError(error));
            }

            let new_state = state | Self::TERMINAL_READY;
            match self.slot.compare_exchange(state, new_state) {
                Ok(()) => break,
                Err(actual) => state = actual,
            }
        }

        let displaced = self.slot.force_push(Item::Error(error));
        self.changed.notify();
        Ok(displaced_bytes(displaced))
    }

    pub fn pop(&self) -> Result<Item, PopError> {
        pop_item(&self.slot, &self.changed)
    }

    /// registers the sole writer-lane waiter
    pub fn register_waiter(&self, waker: &Waker) {
        // Safety: StreamWriter is the only writer-lane registrar for this
        // shared state, so register/unregister never run concurrently.
        unsafe { self.changed.register(waker) };
    }

    /// unregisters the sole writer-lane waiter
    pub fn unregister_waiter(&self) {
        // Safety: StreamWriter is the only writer-lane registrar for this
        // shared state, so register/unregister never run concurrently.
        unsafe { self.changed.unregister() };
    }

    /// returns true once finish was requested and buffered data is drained
    pub fn is_finished(&self) -> bool {
        let state = self.load_state();
        Self::finish_requested(state) && Slot::<Item>::is_empty_state(state)
    }

    pub fn try_read(&self, pending: &mut Bytes, max_len: usize) -> Result<Bytes, ()> {
        if !pending.is_empty() {
            return Ok(if pending.len() <= max_len {
                std::mem::take(pending)
            } else {
                pending.split_to(max_len)
            });
        }

        let state = self.load_state();
        if Self::terminal_ready(state) {
            return Err(());
        }

        match self.pop() {
            Ok(Item::Chunk(mut bytes)) => {
                if bytes.len() <= max_len {
                    Ok(bytes)
                } else {
                    let head = bytes.split_to(max_len);
                    *pending = bytes;
                    Ok(head)
                }
            }
            Ok(Item::Error(_)) => Err(()),
            Err(PopError) => Ok(Bytes::new()),
        }
    }
}

#[inline]
fn try_write_chunk(
    slot: &Slot<Item>,
    changed: &DiatomicWaker,
    bytes: Bytes,
    closed_mask: usize,
) -> Result<(), PushError<Bytes>> {
    match slot.try_push(Item::Chunk(bytes), closed_mask) {
        Ok(()) => {
            changed.notify();
            Ok(())
        }
        Err(PushError::Closed(Item::Chunk(bytes))) => Err(PushError::Closed(bytes)),
        Err(PushError::Full(Item::Chunk(bytes))) => Err(PushError::Full(bytes)),
        Err(PushError::Closed(Item::Error(_)) | PushError::Full(Item::Error(_))) => {
            unreachable!("chunk write cannot recover an error payload")
        }
    }
}

#[inline]
fn displaced_bytes(displaced: Option<Item>) -> Option<Bytes> {
    match displaced {
        Some(Item::Chunk(bytes)) => Some(bytes),
        Some(Item::Error(_)) | None => None,
    }
}

#[inline]
fn pop_item(slot: &Slot<Item>, changed: &DiatomicWaker) -> Result<Item, PopError> {
    match slot.pop() {
        item @ Ok(Item::Chunk(_)) => {
            changed.notify();
            item
        }
        item @ (Ok(Item::Error(_)) | Err(_)) => item,
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use std::task::Waker;

    use bytes::Bytes;
    use loom::thread;
    use ql_wire::StreamCloseCode;

    use super::*;
    use crate::{
        io::{sync::loom::*, Tx},
        QlStreamError,
    };

    #[test]
    fn reader_waiter_registration_survives_finish() {
        check_model(|| {
            let shared = shared();
            shared.rx.register_waiter(Waker::noop());

            let finisher = {
                let shared = shared.clone();
                thread::spawn(move || {
                    shared.rx.finish();
                })
            };

            finisher.join().unwrap();
            assert!(RxInner::is_finished(shared.rx.load_state()));

            shared.rx.unregister_waiter();
        });
    }

    #[test]
    fn reader_chunk_remains_available_after_finish() {
        check_model(|| {
            let shared = shared();

            let producer = {
                let shared = shared.clone();
                thread::spawn(move || {
                    shared.rx.try_write(Bytes::from_static(b"abc")).unwrap();
                    shared.rx.finish();
                })
            };

            producer.join().unwrap();

            match shared.rx.pop() {
                Ok(Item::Chunk(bytes)) => assert_eq!(bytes, Bytes::from_static(b"abc")),
                _ => panic!("expected buffered reader chunk"),
            }
            assert!(RxInner::is_finished(shared.rx.load_state()));
            assert!(matches!(shared.rx.pop(), Err(PopError)));
        });
    }

    #[test]
    fn reader_rejects_write_after_finish() {
        check_model(|| {
            let shared = shared();

            shared.rx.finish();

            assert_eq!(
                shared.rx.try_write(Bytes::from_static(b"abc")),
                Err(PushError::Closed(Bytes::from_static(b"abc")))
            );
            assert!(RxInner::is_finished(shared.rx.load_state()));
            assert!(matches!(shared.rx.pop(), Err(PopError)));
        });
    }

    #[test]
    fn reader_write_races_with_finish_has_coherent_outcome() {
        check_model(|| {
            let shared = shared();

            let writer = {
                let shared = shared.clone();
                thread::spawn(move || shared.rx.try_write(Bytes::from_static(b"abc")))
            };
            let finisher = {
                let shared = shared.clone();
                thread::spawn(move || shared.rx.finish())
            };

            let write_result = writer.join().unwrap();
            finisher.join().unwrap();

            assert!(RxInner::is_finished(shared.rx.load_state()));
            match write_result {
                Ok(()) => match shared.rx.pop() {
                    Ok(Item::Chunk(bytes)) => assert_eq!(bytes, Bytes::from_static(b"abc")),
                    _ => panic!("expected buffered reader chunk"),
                },
                Err(PushError::Closed(bytes)) => {
                    assert_eq!(bytes, Bytes::from_static(b"abc"));
                    assert!(matches!(shared.rx.pop(), Err(PopError)));
                    return;
                }
                Err(PushError::Full(_)) => panic!("empty reader slot must not report full"),
            }
            assert!(matches!(shared.rx.pop(), Err(PopError)));
        });
    }

    #[test]
    fn reader_fail_racing_with_pop_preserves_terminal_outcome() {
        check_model(|| {
            let shared = shared();
            shared.rx.try_write(Bytes::from_static(b"abc")).unwrap();

            let popper = {
                let shared = shared.clone();
                thread::spawn(move || shared.rx.pop())
            };
            let failer = {
                let shared = shared.clone();
                thread::spawn(move || {
                    shared.rx.fail(QlStreamError::StreamClosed {
                        code: StreamCloseCode::CANCELLED,
                    })
                })
            };

            let pop_result = popper.join().unwrap();
            let fail_result = failer.join().unwrap();

            match (pop_result, fail_result) {
                (Ok(Item::Chunk(bytes)), None) => {
                    assert_eq!(bytes, Bytes::from_static(b"abc"));
                    match shared.rx.pop() {
                        Ok(Item::Error(QlStreamError::StreamClosed { code })) => {
                            assert_eq!(code, StreamCloseCode::CANCELLED);
                        }
                        _ => panic!("expected terminal reader error"),
                    }
                }
                (Ok(Item::Error(QlStreamError::StreamClosed { code })), Some(bytes)) => {
                    assert_eq!(code, StreamCloseCode::CANCELLED);
                    assert_eq!(bytes, Bytes::from_static(b"abc"));
                    assert!(matches!(shared.rx.pop(), Err(PopError)));
                }
                _ => panic!("unexpected reader fail/pop race outcome"),
            }
        });
    }

    #[test]
    fn writer_is_finished_only_after_drain() {
        check_model(|| {
            let shared = shared();
            let tx = Tx(shared.clone());
            let mut pending = Bytes::new();

            shared.tx.try_write(Bytes::from_static(b"abc")).unwrap();
            shared.tx.request_finish();

            assert!(!(pending.is_empty() && tx.is_finished()));
            assert_eq!(tx.try_read(&mut pending, 2), Ok(Bytes::from_static(b"ab")));
            assert!(!(pending.is_empty() && tx.is_finished()));
            assert_eq!(tx.try_read(&mut pending, 8), Ok(Bytes::from_static(b"c")));
            assert!(pending.is_empty() && tx.is_finished());
        });
    }

    #[test]
    fn writer_write_races_with_request_finish() {
        check_model(|| {
            let shared = shared();
            let tx = Tx(shared.clone());
            let mut pending = Bytes::new();

            let writer = {
                let shared = shared.clone();
                thread::spawn(move || shared.tx.try_write(Bytes::from_static(b"abc")))
            };
            let finisher = {
                let shared = shared.clone();
                thread::spawn(move || shared.tx.request_finish())
            };

            let write_result = writer.join().unwrap();
            finisher.join().unwrap();

            assert!(TxInner::finish_requested(shared.tx.load_state()));
            match write_result {
                Ok(()) => {
                    assert_eq!(tx.try_read(&mut pending, 8), Ok(Bytes::from_static(b"abc")));
                    assert!(pending.is_empty() && tx.is_finished());
                }
                Err(PushError::Closed(bytes)) => {
                    assert_eq!(bytes, Bytes::from_static(b"abc"));
                    assert!(pending.is_empty() && tx.is_finished());
                }
                Err(PushError::Full(_)) => panic!("empty writer slot must not report full"),
            }
        });
    }

    #[test]
    fn writer_fail_overwrites_buffered_chunk_and_keeps_terminal_state_observable() {
        check_model(|| {
            let shared = shared();
            shared.tx.try_write(Bytes::from_static(b"abc")).unwrap();
            shared.tx.register_waiter(Waker::noop());

            let failer = {
                let shared = shared.clone();
                thread::spawn(move || {
                    let displaced = shared.tx.fail(QlStreamError::StreamClosed {
                        code: StreamCloseCode::CANCELLED,
                    });
                    assert_eq!(displaced.unwrap(), Some(Bytes::from_static(b"abc")));
                })
            };

            failer.join().unwrap();

            assert!(TxInner::terminal_ready(shared.tx.load_state()));
            shared.tx.unregister_waiter();
            match shared.tx.pop() {
                Ok(Item::Error(QlStreamError::StreamClosed { code })) => {
                    assert_eq!(code, StreamCloseCode::CANCELLED);
                }
                _ => panic!("expected terminal writer error"),
            }
        });
    }

    #[test]
    fn reader_waiter_registration_can_be_reused_after_notification() {
        check_model(|| {
            let shared = shared();

            shared.rx.register_waiter(Waker::noop());
            shared.rx.try_write(Bytes::from_static(b"abc")).unwrap();
            match shared.rx.pop() {
                Ok(Item::Chunk(bytes)) => assert_eq!(bytes, Bytes::from_static(b"abc")),
                _ => panic!("expected buffered reader chunk"),
            }

            shared.rx.register_waiter(Waker::noop());
            shared.rx.finish();
            assert!(RxInner::is_finished(shared.rx.load_state()));
            shared.rx.unregister_waiter();
        });
    }

    #[test]
    fn writer_waiter_registration_can_be_reused_after_notification() {
        check_model(|| {
            let shared = shared();

            shared.tx.register_waiter(Waker::noop());
            shared.tx.try_write(Bytes::from_static(b"abc")).unwrap();
            match shared.tx.pop() {
                Ok(Item::Chunk(bytes)) => assert_eq!(bytes, Bytes::from_static(b"abc")),
                _ => panic!("expected buffered writer chunk"),
            }

            shared.tx.register_waiter(Waker::noop());
            shared.tx.finish();
            assert!(TxInner::terminal_ready(shared.tx.load_state()));
            shared.tx.unregister_waiter();
        });
    }

    #[test]
    fn writer_write_races_with_fail() {
        check_model(|| {
            let shared = shared();

            let writer = {
                let shared = shared.clone();
                thread::spawn(move || shared.tx.try_write(Bytes::from_static(b"abc")))
            };
            let failer = {
                let shared = shared.clone();
                thread::spawn(move || {
                    shared.tx.fail(QlStreamError::StreamClosed {
                        code: StreamCloseCode::CANCELLED,
                    })
                })
            };

            let write_result = writer.join().unwrap();
            let fail_result = failer.join().unwrap();

            assert!(TxInner::terminal_ready(shared.tx.load_state()));
            match (&write_result, &fail_result) {
                (Ok(()), Ok(Some(bytes))) => {
                    assert_eq!(Bytes::from_static(b"abc"), bytes.clone());
                }
                (Err(PushError::Closed(bytes)), Ok(None)) => {
                    assert_eq!(Bytes::from_static(b"abc"), bytes.clone());
                }
                (Err(PushError::Full(bytes)), Ok(None)) => {
                    assert_eq!(Bytes::from_static(b"abc"), bytes.clone());
                }
                _ => panic!(
                    "unexpected writer fail/write race outcome: write={write_result:?} fail={fail_result:?}"
                ),
            }

            match shared.tx.pop() {
                Ok(Item::Error(QlStreamError::StreamClosed { code })) => {
                    assert_eq!(code, StreamCloseCode::CANCELLED);
                }
                _ => panic!("expected terminal writer error"),
            }
        });
    }

    #[test]
    fn writer_finish_races_with_fail_without_masking_error() {
        check_model(|| {
            let shared = shared();

            let finisher = {
                let shared = shared.clone();
                thread::spawn(move || shared.tx.finish())
            };
            let failer = {
                let shared = shared.clone();
                thread::spawn(move || {
                    shared.tx.fail(QlStreamError::StreamClosed {
                        code: StreamCloseCode::CANCELLED,
                    })
                })
            };

            finisher.join().unwrap();
            let fail_result = failer.join().unwrap();

            assert!(TxInner::terminal_ready(shared.tx.load_state()));
            match fail_result {
                Err(_) => {
                    assert!(TxInner::terminal_ok(shared.tx.load_state()));
                }
                Ok(_) => {
                    assert!(!TxInner::terminal_ok(shared.tx.load_state()));
                    match shared.tx.pop() {
                        Ok(Item::Error(QlStreamError::StreamClosed { code })) => {
                            assert_eq!(code, StreamCloseCode::CANCELLED);
                        }
                        _ => panic!("expected terminal writer error"),
                    }
                }
            }
        });
    }
}
