mod inner;
mod reader;
mod slot;
mod sync;
mod writer;

use std::ops::Deref;

use ql_common::StreamId;

pub use self::{
    reader::StreamReader,
    slot::PushError,
    writer::{StreamWriter, StreamWriterFinish},
};

pub struct Rx(sync::Arc<inner::Inner>);

impl Deref for Rx {
    type Target = inner::RxInner;

    fn deref(&self) -> &Self::Target {
        &self.0.rx
    }
}

impl Rx {
    pub fn stream_id(&self) -> StreamId {
        self.0.stream_id
    }
}

pub struct Tx(sync::Arc<inner::Inner>);

impl Deref for Tx {
    type Target = inner::TxInner;

    fn deref(&self) -> &Self::Target {
        &self.0.tx
    }
}

impl Tx {
    pub fn stream_id(&self) -> StreamId {
        self.0.stream_id
    }
}

pub fn new_stream(
    stream_id: StreamId,
    runtime_tx: async_channel::Sender<crate::command::Command>,
) -> (StreamReader, StreamWriter, Rx, Tx) {
    let shared = inner::new(stream_id);
    (
        StreamReader::new(Rx(shared.clone()), runtime_tx.clone()),
        StreamWriter::new(Tx(shared.clone()), runtime_tx),
        Rx(shared.clone()),
        Tx(shared),
    )
}
