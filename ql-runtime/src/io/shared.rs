use bytes::Bytes;
use event_listener::{Event, EventListener};
use ql_wire::StreamId;

use super::{
    queue::{ForcePushError, PopError, PushError, Single},
    sync::{Arc, AtomicU8, Ordering},
};
use crate::QlStreamError;

const READER_FINISHED: u8 = 1 << 0;

const WRITER_FINISH_REQUESTED: u8 = 1 << 0;
const WRITER_TERMINAL_READY: u8 = 1 << 1;
const WRITER_TERMINAL_OK: u8 = 1 << 2;

pub struct StreamShared {
    pub stream_id: StreamId,
    pub reader: ReaderShared,
    pub writer: WriterShared,
}

impl StreamShared {
    pub fn new(stream_id: StreamId) -> Arc<Self> {
        Arc::new(Self {
            stream_id,
            reader: ReaderShared::new(),
            writer: WriterShared::new(),
        })
    }
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

pub struct ReaderShared {
    slot: Single<Item>,
    changed: Event,
    state: AtomicU8,
}

impl ReaderShared {
    fn new() -> Self {
        Self {
            slot: Single::new(),
            changed: Event::new(),
            state: AtomicU8::new(0),
        }
    }

    pub fn try_write(&self, bytes: Bytes) -> Result<(), PushError<Bytes>> {
        if Self::is_finished(self.load_state()) {
            return Err(PushError::Closed(bytes));
        }

        match self.slot.push(Item::Chunk(bytes)) {
            Ok(()) => {
                self.changed.notify(usize::MAX);
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
            self.changed.notify(usize::MAX);
        }
    }

    pub fn fail(
        &self,
        error: QlStreamError,
    ) -> Result<Option<Bytes>, ForcePushError<QlStreamError>> {
        match self.slot.force_push(Item::Error(error)) {
            Ok(displaced) => {
                self.changed.notify(usize::MAX);
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
                self.changed.notify(usize::MAX);
                Ok(Item::Chunk(bytes))
            }
            Ok(Item::Error(error)) => Ok(Item::Error(error)),
            Err(error) => Err(error),
        }
    }

    pub fn listen(&self) -> EventListener {
        self.changed.listen()
    }
}

pub struct WriterShared {
    slot: Single<Item>,
    changed: Event,
    state: AtomicU8,
}

impl WriterShared {
    fn new() -> Self {
        Self {
            slot: Single::new(),
            changed: Event::new(),
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
                self.changed.notify(usize::MAX);
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
            self.changed.notify(usize::MAX);
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
                    self.changed.notify(usize::MAX);
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
                self.changed.notify(usize::MAX);
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
                self.changed.notify(usize::MAX);
                Ok(Item::Chunk(bytes))
            }
            Ok(Item::Error(error)) => Ok(Item::Error(error)),
            Err(error) => Err(error),
        }
    }

    pub fn listen(&self) -> EventListener {
        self.changed.listen()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvClosed;

pub struct ReaderIo {
    shared: Arc<StreamShared>,
}

impl ReaderIo {
    pub fn new(shared: Arc<StreamShared>) -> Self {
        Self { shared }
    }

    pub fn try_write(&self, bytes: Bytes) -> Result<(), PushError<Bytes>> {
        self.shared.reader.try_write(bytes)
    }

    pub fn finish(&self) {
        self.shared.reader.finish();
    }

    pub fn fail(
        &self,
        error: QlStreamError,
    ) -> Result<Option<Bytes>, ForcePushError<QlStreamError>> {
        self.shared.reader.fail(error)
    }
}

pub struct WriterIo {
    shared: Arc<StreamShared>,
    pending: Bytes,
}

impl WriterIo {
    pub fn new(shared: Arc<StreamShared>) -> Self {
        Self {
            shared,
            pending: Bytes::new(),
        }
    }

    pub fn is_finished(&self) -> bool {
        let state = self.shared.writer.load_state();
        self.pending.is_empty()
            && WriterShared::finish_requested(state)
            && self.shared.writer.is_empty()
    }

    pub fn try_read(&mut self, max_len: usize) -> Result<Bytes, RecvClosed> {
        if !self.pending.is_empty() {
            let pending = &mut self.pending;
            let bytes = if pending.len() <= max_len {
                std::mem::take(pending)
            } else {
                pending.split_to(max_len)
            };
            return Ok(bytes);
        }

        let state = self.shared.writer.load_state();
        if WriterShared::terminal_ready(state) {
            return Err(RecvClosed);
        }

        match self.shared.writer.pop() {
            Ok(Item::Chunk(mut bytes)) => {
                if bytes.len() <= max_len {
                    Ok(bytes)
                } else {
                    let head = bytes.split_to(max_len);
                    self.pending = bytes;
                    Ok(head)
                }
            }
            Ok(Item::Error(_)) => Err(RecvClosed),
            Err(PopError::Empty) => Ok(Bytes::new()),
            Err(PopError::Closed) => Err(RecvClosed),
        }
    }

    pub fn finish(&self) {
        self.shared.writer.finish();
    }

    pub fn fail(
        &self,
        error: QlStreamError,
    ) -> Result<Option<Bytes>, ForcePushError<QlStreamError>> {
        self.shared.writer.fail(error)
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use bytes::Bytes;
    use loom::{model, thread};
    use ql_wire::{StreamCloseCode, StreamId};

    use super::{Item, PopError, PushError, ReaderShared, StreamShared, WriterIo, WriterShared};
    use crate::QlStreamError;

    fn check_model(f: impl Fn() + Sync + Send + 'static) {
        let builder = model::Builder::new();
        builder.check(f);
    }

    fn shared() -> super::super::sync::Arc<StreamShared> {
        StreamShared::new(StreamId(1u32.into()))
    }

    #[test]
    fn reader_listener_observes_finish_after_pending() {
        check_model(|| {
            let shared = shared();
            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            let mut listener = pin!(shared.reader.listen());

            assert!(matches!(listener.as_mut().poll(&mut cx), Poll::Pending));

            let finisher = {
                let shared = shared.clone();
                thread::spawn(move || {
                    shared.reader.finish();
                })
            };

            finisher.join().unwrap();
            assert!(ReaderShared::is_finished(shared.reader.load_state()));
            assert!(matches!(listener.as_mut().poll(&mut cx), Poll::Ready(())));
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
            assert!(ReaderShared::is_finished(shared.reader.load_state()));
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
            assert!(ReaderShared::is_finished(shared.reader.load_state()));
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

            assert!(ReaderShared::is_finished(shared.reader.load_state()));
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
            let mut writer_io = WriterIo::new(shared.clone());

            shared.writer.try_write(Bytes::from_static(b"abc")).unwrap();
            shared.writer.request_finish();

            assert!(!writer_io.is_finished());
            assert_eq!(writer_io.try_read(2), Ok(Bytes::from_static(b"ab")));
            assert!(!writer_io.is_finished());
            assert_eq!(writer_io.try_read(8), Ok(Bytes::from_static(b"c")));
            assert!(writer_io.is_finished());
        });
    }

    #[test]
    fn writer_write_races_with_request_finish() {
        check_model(|| {
            let shared = shared();
            let mut writer_io = WriterIo::new(shared.clone());

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

            assert!(WriterShared::finish_requested(shared.writer.load_state()));
            match write_result {
                Ok(()) => {
                    assert_eq!(writer_io.try_read(8), Ok(Bytes::from_static(b"abc")));
                    assert!(writer_io.is_finished());
                }
                Err(PushError::Closed(bytes)) => {
                    assert_eq!(bytes, Bytes::from_static(b"abc"));
                    assert!(writer_io.is_finished());
                }
                Err(PushError::Full(_)) => panic!("empty writer slot must not report full"),
            }
        });
    }

    #[test]
    fn writer_fail_overwrites_buffered_chunk_and_wakes_listener() {
        check_model(|| {
            let shared = shared();
            shared.writer.try_write(Bytes::from_static(b"abc")).unwrap();

            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            let mut listener = pin!(shared.writer.listen());
            assert!(matches!(listener.as_mut().poll(&mut cx), Poll::Pending));

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

            assert!(WriterShared::terminal_ready(shared.writer.load_state()));
            assert!(matches!(listener.as_mut().poll(&mut cx), Poll::Ready(())));
            match shared.writer.pop() {
                Ok(Item::Error(QlStreamError::StreamClosed { code })) => {
                    assert_eq!(code, StreamCloseCode::CANCELLED);
                }
                _ => panic!("expected terminal writer error"),
            }
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

            assert!(WriterShared::terminal_ready(shared.writer.load_state()));
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

            assert!(WriterShared::terminal_ready(shared.writer.load_state()));
            match fail_result {
                Err(_) => {
                    assert!(WriterShared::terminal_ok(shared.writer.load_state()));
                }
                Ok(_) => {
                    assert!(!WriterShared::terminal_ok(shared.writer.load_state()));
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
