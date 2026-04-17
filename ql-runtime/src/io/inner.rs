use std::task::Waker;

use bytes::Bytes;
use diatomic_waker::DiatomicWaker;
use ql_wire::StreamId;

use super::{
    queue::{ForcePushError, PopError, PushError, Single},
    sync::{AtomicU8, Ordering},
};
use crate::QlStreamError;

const READER_FINISHED: u8 = 1 << 0;

const WRITER_FINISH_REQUESTED: u8 = 1 << 0;
const WRITER_TERMINAL_READY: u8 = 1 << 1;
const WRITER_TERMINAL_OK: u8 = 1 << 2;

pub(super) fn new(stream_id: StreamId) -> Inner {
    Inner {
        stream_id,
        reader: RxInner::new(),
        writer: TxInner::new(),
    }
}

pub(super) struct Inner {
    pub(super) stream_id: StreamId,
    pub(super) reader: RxInner,
    pub(super) writer: TxInner,
}

pub enum Item {
    Chunk(Bytes),
    Error(QlStreamError),
}

impl Item {
    fn into_chunk(self) -> Option<Bytes> {
        match self {
            Self::Chunk(bytes) => Some(bytes),
            Self::Error(_) => None,
        }
    }
}

pub struct RxInner {
    slot: Single<Item>,
    changed: DiatomicWaker,
    state: AtomicU8,
}

impl RxInner {
    fn new() -> Self {
        Self {
            slot: Single::new(),
            changed: DiatomicWaker::new(),
            state: AtomicU8::new(0),
        }
    }

    pub fn try_write(&self, bytes: Bytes) -> Result<(), PushError<Bytes>> {
        if Self::is_finished(self.load_state()) {
            return Err(PushError::Closed(bytes));
        }

        match self.slot.push(Item::Chunk(bytes)) {
            Ok(()) => {
                self.changed.notify();
                Ok(())
            }
            Err(PushError::Closed(Item::Chunk(bytes))) => Err(PushError::Closed(bytes)),
            Err(PushError::Full(Item::Chunk(bytes))) => Err(PushError::Full(bytes)),
            Err(PushError::Closed(Item::Error(_))) | Err(PushError::Full(Item::Error(_))) => {
                unreachable!("reader chunk write cannot recover an error payload")
            }
        }
    }

    pub fn finish(&self) {
        if self.state.fetch_or(READER_FINISHED, Ordering::Release) & READER_FINISHED == 0 {
            self.changed.notify();
        }
    }

    pub fn fail(
        &self,
        error: QlStreamError,
    ) -> Result<Option<Bytes>, ForcePushError<QlStreamError>> {
        match self.slot.force_push(Item::Error(error)) {
            Ok(displaced) => {
                self.changed.notify();
                Ok(displaced.and_then(Item::into_chunk))
            }
            Err(ForcePushError(Item::Error(error))) => Err(ForcePushError(error)),
            Err(ForcePushError(Item::Chunk(_))) => {
                unreachable!("reader fail cannot recover a chunk payload")
            }
        }
    }

    pub fn load_state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    pub fn is_finished(state: u8) -> bool {
        state & READER_FINISHED != 0
    }

    pub fn pop(&self) -> Result<Item, PopError> {
        match self.slot.pop() {
            Ok(Item::Chunk(bytes)) => {
                self.changed.notify();
                Ok(Item::Chunk(bytes))
            }
            Ok(Item::Error(error)) => Ok(Item::Error(error)),
            Err(error) => Err(error),
        }
    }

    pub fn register_waiter(&self, waker: &Waker) {
        // Safety: StreamReader is the only reader-side registrar for this
        // shared state, so register/unregister never run concurrently.
        unsafe { self.changed.register(waker) };
    }

    pub fn unregister_waiter(&self) {
        // Safety: StreamReader is the only reader-side registrar for this
        // shared state, so register/unregister never run concurrently.
        unsafe { self.changed.unregister() };
    }
}

pub struct TxInner {
    slot: Single<Item>,
    changed: DiatomicWaker,
    state: AtomicU8,
}

impl TxInner {
    fn new() -> Self {
        Self {
            slot: Single::new(),
            changed: DiatomicWaker::new(),
            state: AtomicU8::new(0),
        }
    }

    pub fn load_state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    pub fn finish_requested(state: u8) -> bool {
        state & WRITER_FINISH_REQUESTED != 0
    }

    pub fn terminal_ready(state: u8) -> bool {
        state & WRITER_TERMINAL_READY != 0
    }

    pub fn terminal_ok(state: u8) -> bool {
        state & WRITER_TERMINAL_OK != 0
    }

    pub fn try_write(&self, bytes: Bytes) -> Result<(), PushError<Bytes>> {
        let state = self.load_state();
        if Self::terminal_ready(state) || Self::finish_requested(state) {
            return Err(PushError::Closed(bytes));
        }

        match self.slot.push(Item::Chunk(bytes)) {
            Ok(()) => {
                self.changed.notify();
                Ok(())
            }
            Err(PushError::Closed(Item::Chunk(bytes))) => Err(PushError::Closed(bytes)),
            Err(PushError::Full(Item::Chunk(bytes))) => Err(PushError::Full(bytes)),
            Err(PushError::Closed(Item::Error(_))) | Err(PushError::Full(Item::Error(_))) => {
                unreachable!("writer chunk write cannot recover an error payload")
            }
        }
    }

    pub fn request_finish(&self) {
        if self
            .state
            .fetch_or(WRITER_FINISH_REQUESTED, Ordering::Release)
            & WRITER_FINISH_REQUESTED
            == 0
        {
            self.changed.notify();
        }
    }

    pub fn finish(&self) {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if Self::terminal_ready(state) {
                return;
            }

            let new_state = state | WRITER_TERMINAL_READY | WRITER_TERMINAL_OK;
            match self
                .state
                .compare_exchange(state, new_state, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    self.changed.notify();
                    return;
                }
                Err(actual) => state = actual,
            }
        }
    }

    pub fn fail(
        &self,
        error: QlStreamError,
    ) -> Result<Option<Bytes>, ForcePushError<QlStreamError>> {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if Self::terminal_ready(state) {
                return Err(ForcePushError(error));
            }

            let new_state = state | WRITER_TERMINAL_READY;
            match self
                .state
                .compare_exchange(state, new_state, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => state = actual,
            }
        }

        match self.slot.force_push(Item::Error(error)) {
            Ok(displaced) => {
                self.changed.notify();
                Ok(displaced.and_then(Item::into_chunk))
            }
            Err(ForcePushError(Item::Error(error))) => Err(ForcePushError(error)),
            Err(ForcePushError(Item::Chunk(_))) => {
                unreachable!("writer fail cannot recover a chunk payload")
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.slot.is_empty()
    }

    pub fn pop(&self) -> Result<Item, PopError> {
        match self.slot.pop() {
            Ok(Item::Chunk(bytes)) => {
                self.changed.notify();
                Ok(Item::Chunk(bytes))
            }
            Ok(Item::Error(error)) => Ok(Item::Error(error)),
            Err(error) => Err(error),
        }
    }

    pub fn register_waiter(&self, waker: &Waker) {
        // Safety: StreamWriter is the only writer-side registrar for this
        // shared state, so register/unregister never run concurrently.
        unsafe { self.changed.register(waker) };
    }

    pub fn unregister_waiter(&self) {
        // Safety: StreamWriter is the only writer-side registrar for this
        // shared state, so register/unregister never run concurrently.
        unsafe { self.changed.unregister() };
    }

    pub fn is_finished(&self) -> bool {
        let state = self.load_state();
        TxInner::finish_requested(state) && self.is_empty()
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
        if TxInner::terminal_ready(state) {
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
            Err(PopError::Empty) => Ok(Bytes::new()),
            Err(PopError::Closed) => Err(()),
        }
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use std::task::Waker;

    use bytes::Bytes;
    use loom::{model, thread};
    use ql_wire::{StreamCloseCode, StreamId};

    use super::*;
    use crate::{io::Tx, QlStreamError};

    fn check_model(f: impl Fn() + Sync + Send + 'static) {
        let builder = model::Builder::new();
        builder.check(f);
    }

    fn shared() -> super::super::sync::Arc<Inner> {
        super::super::sync::Arc::new(new(StreamId(1u32.into())))
    }

    #[test]
    fn reader_waiter_registration_survives_finish() {
        check_model(|| {
            let shared = shared();
            shared.reader.register_waiter(Waker::noop());

            let finisher = {
                let shared = shared.clone();
                thread::spawn(move || {
                    shared.reader.finish();
                })
            };

            finisher.join().unwrap();
            assert!(RxInner::is_finished(shared.reader.load_state()));

            shared.reader.unregister_waiter();
        });
    }

    #[test]
    fn reader_chunk_remains_available_after_finish() {
        check_model(|| {
            let shared = shared();

            let producer = {
                let shared = shared.clone();
                thread::spawn(move || {
                    shared.reader.try_write(Bytes::from_static(b"abc")).unwrap();
                    shared.reader.finish();
                })
            };

            producer.join().unwrap();

            match shared.reader.pop() {
                Ok(Item::Chunk(bytes)) => assert_eq!(bytes, Bytes::from_static(b"abc")),
                _ => panic!("expected buffered reader chunk"),
            }
            assert!(RxInner::is_finished(shared.reader.load_state()));
            assert!(matches!(shared.reader.pop(), Err(PopError::Empty)));
        });
    }

    #[test]
    fn reader_rejects_write_after_finish() {
        check_model(|| {
            let shared = shared();

            shared.reader.finish();

            assert_eq!(
                shared.reader.try_write(Bytes::from_static(b"abc")),
                Err(PushError::Closed(Bytes::from_static(b"abc")))
            );
            assert!(RxInner::is_finished(shared.reader.load_state()));
            assert!(matches!(shared.reader.pop(), Err(PopError::Empty)));
        });
    }

    #[test]
    fn reader_write_races_with_finish_has_coherent_outcome() {
        check_model(|| {
            let shared = shared();

            let writer = {
                let shared = shared.clone();
                thread::spawn(move || shared.reader.try_write(Bytes::from_static(b"abc")))
            };
            let finisher = {
                let shared = shared.clone();
                thread::spawn(move || shared.reader.finish())
            };

            let write_result = writer.join().unwrap();
            finisher.join().unwrap();

            assert!(RxInner::is_finished(shared.reader.load_state()));
            match write_result {
                Ok(()) => match shared.reader.pop() {
                    Ok(Item::Chunk(bytes)) => assert_eq!(bytes, Bytes::from_static(b"abc")),
                    _ => panic!("expected buffered reader chunk"),
                },
                Err(PushError::Closed(bytes)) => {
                    assert_eq!(bytes, Bytes::from_static(b"abc"));
                    assert!(matches!(shared.reader.pop(), Err(PopError::Empty)));
                    return;
                }
                Err(PushError::Full(_)) => panic!("empty reader slot must not report full"),
            }
            assert!(matches!(shared.reader.pop(), Err(PopError::Empty)));
        });
    }

    #[test]
    fn reader_fail_racing_with_pop_preserves_terminal_outcome() {
        check_model(|| {
            let shared = shared();
            shared.reader.try_write(Bytes::from_static(b"abc")).unwrap();

            let popper = {
                let shared = shared.clone();
                thread::spawn(move || shared.reader.pop())
            };
            let failer = {
                let shared = shared.clone();
                thread::spawn(move || {
                    shared.reader.fail(QlStreamError::StreamClosed {
                        code: StreamCloseCode::CANCELLED,
                    })
                })
            };

            let pop_result = popper.join().unwrap();
            let fail_result = failer.join().unwrap();

            match (pop_result, fail_result) {
                (Ok(Item::Chunk(bytes)), Ok(None)) => {
                    assert_eq!(bytes, Bytes::from_static(b"abc"));
                    match shared.reader.pop() {
                        Ok(Item::Error(QlStreamError::StreamClosed { code })) => {
                            assert_eq!(code, StreamCloseCode::CANCELLED);
                        }
                        _ => panic!("expected terminal reader error"),
                    }
                }
                (Ok(Item::Error(QlStreamError::StreamClosed { code })), Ok(Some(bytes))) => {
                    assert_eq!(code, StreamCloseCode::CANCELLED);
                    assert_eq!(bytes, Bytes::from_static(b"abc"));
                    assert!(matches!(shared.reader.pop(), Err(PopError::Empty)));
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

            shared.writer.try_write(Bytes::from_static(b"abc")).unwrap();
            shared.writer.request_finish();

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
                thread::spawn(move || shared.writer.try_write(Bytes::from_static(b"abc")))
            };
            let finisher = {
                let shared = shared.clone();
                thread::spawn(move || shared.writer.request_finish())
            };

            let write_result = writer.join().unwrap();
            finisher.join().unwrap();

            assert!(TxInner::finish_requested(shared.writer.load_state()));
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
            shared.writer.try_write(Bytes::from_static(b"abc")).unwrap();
            shared.writer.register_waiter(Waker::noop());

            let failer = {
                let shared = shared.clone();
                thread::spawn(move || {
                    let displaced = shared.writer.fail(QlStreamError::StreamClosed {
                        code: StreamCloseCode::CANCELLED,
                    });
                    assert_eq!(displaced.unwrap(), Some(Bytes::from_static(b"abc")));
                })
            };

            failer.join().unwrap();

            assert!(TxInner::terminal_ready(shared.writer.load_state()));
            shared.writer.unregister_waiter();
            match shared.writer.pop() {
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

            shared.reader.register_waiter(Waker::noop());
            shared.reader.try_write(Bytes::from_static(b"abc")).unwrap();
            match shared.reader.pop() {
                Ok(Item::Chunk(bytes)) => assert_eq!(bytes, Bytes::from_static(b"abc")),
                _ => panic!("expected buffered reader chunk"),
            }

            shared.reader.register_waiter(Waker::noop());
            shared.reader.finish();
            assert!(RxInner::is_finished(shared.reader.load_state()));
            shared.reader.unregister_waiter();
        });
    }

    #[test]
    fn writer_waiter_registration_can_be_reused_after_notification() {
        check_model(|| {
            let shared = shared();

            shared.writer.register_waiter(Waker::noop());
            shared.writer.try_write(Bytes::from_static(b"abc")).unwrap();
            match shared.writer.pop() {
                Ok(Item::Chunk(bytes)) => assert_eq!(bytes, Bytes::from_static(b"abc")),
                _ => panic!("expected buffered writer chunk"),
            }

            shared.writer.register_waiter(Waker::noop());
            shared.writer.finish();
            assert!(TxInner::terminal_ready(shared.writer.load_state()));
            shared.writer.unregister_waiter();
        });
    }

    #[test]
    fn writer_write_races_with_fail() {
        check_model(|| {
            let shared = shared();

            let writer = {
                let shared = shared.clone();
                thread::spawn(move || shared.writer.try_write(Bytes::from_static(b"abc")))
            };
            let failer = {
                let shared = shared.clone();
                thread::spawn(move || {
                    shared.writer.fail(QlStreamError::StreamClosed {
                        code: StreamCloseCode::CANCELLED,
                    })
                })
            };

            let write_result = writer.join().unwrap();
            let fail_result = failer.join().unwrap();

            assert!(TxInner::terminal_ready(shared.writer.load_state()));
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

            match shared.writer.pop() {
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
                thread::spawn(move || shared.writer.finish())
            };
            let failer = {
                let shared = shared.clone();
                thread::spawn(move || {
                    shared.writer.fail(QlStreamError::StreamClosed {
                        code: StreamCloseCode::CANCELLED,
                    })
                })
            };

            finisher.join().unwrap();
            let fail_result = failer.join().unwrap();

            assert!(TxInner::terminal_ready(shared.writer.load_state()));
            match fail_result {
                Err(_) => {
                    assert!(TxInner::terminal_ok(shared.writer.load_state()));
                }
                Ok(_) => {
                    assert!(!TxInner::terminal_ok(shared.writer.load_state()));
                    match shared.writer.pop() {
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
