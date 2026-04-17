use bytes::Bytes;
use event_listener::{Event, EventListener};
use ql_wire::StreamId;

use super::{
    queue::{ForcePushError, PopError, PushError, Single},
    sync::{Arc, AtomicUsize, Ordering},
};
use crate::QlStreamError;

const READER_FINISHED: usize = 1 << 0;

const WRITER_FINISH_REQUESTED: usize = 1 << 0;
const WRITER_TERMINAL_READY: usize = 1 << 1;
const WRITER_TERMINAL_OK: usize = 1 << 2;

pub(crate) struct StreamShared {
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

enum SlotMsg {
    Chunk(Bytes),
    Error(QlStreamError),
}

impl SlotMsg {
    fn into_chunk(self) -> Option<Bytes> {
        match self {
            Self::Chunk(bytes) => Some(bytes),
            Self::Error(_) => None,
        }
    }
}

pub(crate) struct ReaderShared {
    slot: Single<SlotMsg>,
    changed: Event,
    state: AtomicUsize,
}

impl ReaderShared {
    fn new() -> Self {
        Self {
            slot: Single::new(),
            changed: Event::new(),
            state: AtomicUsize::new(0),
        }
    }

    pub fn try_write(&self, bytes: Bytes) -> Result<(), PushError<Bytes>> {
        match self.slot.push(SlotMsg::Chunk(bytes)) {
            Ok(()) => {
                self.changed.notify(usize::MAX);
                Ok(())
            }
            Err(PushError::Closed(SlotMsg::Chunk(bytes))) => Err(PushError::Closed(bytes)),
            Err(PushError::Full(SlotMsg::Chunk(bytes))) => Err(PushError::Full(bytes)),
            Err(PushError::Closed(SlotMsg::Error(_))) | Err(PushError::Full(SlotMsg::Error(_))) => {
                unreachable!("reader chunk write cannot recover an error payload")
            }
        }
    }

    pub fn finish(&self) {
        if self.state.fetch_or(READER_FINISHED, Ordering::SeqCst) & READER_FINISHED == 0 {
            self.changed.notify(usize::MAX);
        }
    }

    pub fn fail(
        &self,
        error: QlStreamError,
    ) -> Result<Option<Bytes>, ForcePushError<QlStreamError>> {
        match self.slot.force_push(SlotMsg::Error(error)) {
            Ok(displaced) => {
                self.changed.notify(usize::MAX);
                Ok(displaced.and_then(SlotMsg::into_chunk))
            }
            Err(ForcePushError(SlotMsg::Error(error))) => Err(ForcePushError(error)),
            Err(ForcePushError(SlotMsg::Chunk(_))) => {
                unreachable!("reader fail cannot recover a chunk payload")
            }
        }
    }

    pub fn is_finished(&self) -> bool {
        self.state.load(Ordering::SeqCst) & READER_FINISHED != 0
    }

    pub fn pop(&self) -> Result<ReaderItem, PopError> {
        match self.slot.pop() {
            Ok(SlotMsg::Chunk(bytes)) => {
                self.changed.notify(usize::MAX);
                Ok(ReaderItem::Chunk(bytes))
            }
            Ok(SlotMsg::Error(error)) => Ok(ReaderItem::Error(error)),
            Err(error) => Err(error),
        }
    }

    pub fn listen(&self) -> EventListener {
        self.changed.listen()
    }
}

pub(crate) enum ReaderItem {
    Chunk(Bytes),
    Error(QlStreamError),
}

pub(crate) struct WriterShared {
    slot: Single<SlotMsg>,
    changed: Event,
    state: AtomicUsize,
}

impl WriterShared {
    fn new() -> Self {
        Self {
            slot: Single::new(),
            changed: Event::new(),
            state: AtomicUsize::new(0),
        }
    }

    pub fn try_write(&self, bytes: Bytes) -> Result<(), PushError<Bytes>> {
        if self.terminal_ready() || self.finish_requested() {
            return Err(PushError::Closed(bytes));
        }

        match self.slot.push(SlotMsg::Chunk(bytes)) {
            Ok(()) => {
                self.changed.notify(usize::MAX);
                Ok(())
            }
            Err(PushError::Closed(SlotMsg::Chunk(bytes))) => Err(PushError::Closed(bytes)),
            Err(PushError::Full(SlotMsg::Chunk(bytes))) => Err(PushError::Full(bytes)),
            Err(PushError::Closed(SlotMsg::Error(_))) | Err(PushError::Full(SlotMsg::Error(_))) => {
                unreachable!("writer chunk write cannot recover an error payload")
            }
        }
    }

    pub fn request_finish(&self) {
        if self
            .state
            .fetch_or(WRITER_FINISH_REQUESTED, Ordering::SeqCst)
            & WRITER_FINISH_REQUESTED
            == 0
        {
            self.changed.notify(usize::MAX);
        }
    }

    pub fn finish_requested(&self) -> bool {
        self.state.load(Ordering::SeqCst) & WRITER_FINISH_REQUESTED != 0
    }

    pub fn finish(&self) {
        self.state
            .fetch_or(WRITER_TERMINAL_READY | WRITER_TERMINAL_OK, Ordering::SeqCst);
        self.changed.notify(usize::MAX);
    }

    pub fn fail(
        &self,
        error: QlStreamError,
    ) -> Result<Option<Bytes>, ForcePushError<QlStreamError>> {
        if self.terminal_ready() {
            return Err(ForcePushError(error));
        }

        match self.slot.force_push(SlotMsg::Error(error)) {
            Ok(displaced) => {
                self.state.fetch_or(WRITER_TERMINAL_READY, Ordering::SeqCst);
                self.changed.notify(usize::MAX);
                Ok(displaced.and_then(SlotMsg::into_chunk))
            }
            Err(ForcePushError(SlotMsg::Error(error))) => Err(ForcePushError(error)),
            Err(ForcePushError(SlotMsg::Chunk(_))) => {
                unreachable!("writer fail cannot recover a chunk payload")
            }
        }
    }

    pub fn terminal_ready(&self) -> bool {
        self.state.load(Ordering::SeqCst) & WRITER_TERMINAL_READY != 0
    }

    pub fn terminal_ok(&self) -> bool {
        self.state.load(Ordering::SeqCst) & WRITER_TERMINAL_OK != 0
    }

    pub fn is_empty(&self) -> bool {
        self.slot.is_empty()
    }

    pub fn pop(&self) -> Result<WriterItem, PopError> {
        match self.slot.pop() {
            Ok(SlotMsg::Chunk(bytes)) => {
                self.changed.notify(usize::MAX);
                Ok(WriterItem::Chunk(bytes))
            }
            Ok(SlotMsg::Error(error)) => Ok(WriterItem::Error(error)),
            Err(error) => Err(error),
        }
    }

    pub fn listen(&self) -> EventListener {
        self.changed.listen()
    }
}

pub(crate) enum WriterItem {
    Chunk(Bytes),
    Error(QlStreamError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecvClosed;

pub(crate) struct ReaderIo {
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

pub(crate) struct WriterIo {
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
        self.pending.is_empty()
            && self.shared.writer.finish_requested()
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

        if self.shared.writer.terminal_ready() {
            return Err(RecvClosed);
        }

        match self.shared.writer.pop() {
            Ok(WriterItem::Chunk(mut bytes)) => {
                if bytes.len() <= max_len {
                    Ok(bytes)
                } else {
                    let head = bytes.split_to(max_len);
                    self.pending = bytes;
                    Ok(head)
                }
            }
            Ok(WriterItem::Error(_)) => Err(RecvClosed),
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
