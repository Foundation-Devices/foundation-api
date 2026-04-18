mod inner;
mod queue;
mod reader;
mod sync;
mod writer;

use std::ops::Deref;

use ql_wire::{CloseTarget, StreamId};

pub(crate) use self::queue::PushError;
pub use self::{reader::StreamReader, writer::StreamWriter};
use crate::RuntimeHandle;

pub(crate) struct Rx(sync::Arc<inner::Inner>);

impl Deref for Rx {
    type Target = inner::RxInner;

    fn deref(&self) -> &Self::Target {
        &self.0.reader
    }
}

impl Rx {
    pub fn stream_id(&self) -> StreamId {
        self.0.stream_id
    }
}

pub(crate) struct Tx(sync::Arc<inner::Inner>);

impl Deref for Tx {
    type Target = inner::TxInner;

    fn deref(&self) -> &Self::Target {
        &self.0.writer
    }
}

impl Tx {
    pub fn stream_id(&self) -> StreamId {
        self.0.stream_id
    }
}

pub(crate) fn new_stream(
    stream_id: StreamId,
    reader_target: CloseTarget,
    writer_target: CloseTarget,
    handle: RuntimeHandle,
) -> (StreamReader, StreamWriter, Rx, Tx) {
    let shared = sync::Arc::new(inner::new(stream_id));
    (
        StreamReader::new(Rx(shared.clone()), reader_target, handle.clone()),
        StreamWriter::new(Tx(shared.clone()), writer_target, handle),
        Rx(shared.clone()),
        Tx(shared),
    )
}
