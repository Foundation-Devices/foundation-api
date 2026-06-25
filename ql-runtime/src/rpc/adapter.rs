use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use ql_rpc::{ResetCode, RpcRead, RpcStream, RpcWrite};

use crate::{QlStream, QlStreamError, StreamReader, StreamWriter};

impl RpcStream for QlStream {
    type Error = QlStreamError;
    type Reader = StreamReader;
    type Writer = StreamWriter;

    fn split(self) -> (Self::Reader, Self::Writer) {
        (self.reader, self.writer)
    }
}

impl RpcRead for StreamReader {
    type Error = QlStreamError;

    fn poll_read(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Option<Bytes>, QlStreamError>> {
        StreamReader::poll_read(self, cx)
    }

    fn reset(self, code: ResetCode) {
        StreamReader::reset(self, code);
    }
}

impl RpcWrite for StreamWriter {
    type Error = QlStreamError;

    fn poll_write(
        &mut self,
        bytes: &mut Bytes,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), QlStreamError>> {
        StreamWriter::poll_write(self, bytes, cx)
    }

    fn queue_finish(&mut self) {
        StreamWriter::queue_finish(self);
    }

    fn poll_finish(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), QlStreamError>> {
        StreamWriter::poll_finish(self, cx)
    }

    fn reset(self, code: ResetCode) {
        StreamWriter::reset(self, code);
    }
}
