mod queue;
mod reader;
mod shared;
mod sync;
mod writer;

use ql_wire::{CloseTarget, StreamId};

use self::shared::StreamShared;
pub(crate) use self::{
    queue::PushError,
    shared::{ReaderIo, WriterIo},
};
pub use self::{reader::StreamReader, writer::StreamWriter};
use crate::RuntimeHandle;

pub(crate) struct StreamIo {
    pub reader: StreamReader,
    pub writer: StreamWriter,
    pub reader_io: ReaderIo,
    pub writer_io: WriterIo,
}

pub(crate) fn new_stream(
    stream_id: StreamId,
    reader_target: CloseTarget,
    writer_target: CloseTarget,
    handle: RuntimeHandle,
) -> StreamIo {
    let shared = StreamShared::new(stream_id);
    StreamIo {
        reader: StreamReader::new(shared.clone(), reader_target, handle.clone()),
        writer: StreamWriter::new(shared.clone(), writer_target, handle),
        reader_io: ReaderIo::new(shared.clone()),
        writer_io: WriterIo::new(shared),
    }
}
