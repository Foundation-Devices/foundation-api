use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use ql_common::ResetCode;
use ql_rpc::{RpcRead, RpcStream, RpcWrite};

use crate::{QlStream, QlStreamError, StreamReader, StreamWriter, StreamWriterFinish};

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

    fn poll_read(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<Bytes, QlStreamError>> {
        StreamReader::poll_read(self, cx)
    }

    fn reset(&mut self, code: ResetCode) {
        StreamReader::reset(self, code);
    }
}

impl RpcWrite for StreamWriter {
    type Error = QlStreamError;
    type Finish = StreamWriterFinish;

    fn poll_write(
        &mut self,
        bytes: &mut Bytes,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), QlStreamError>> {
        StreamWriter::poll_write(self, bytes, cx)
    }

    fn finish(self) -> Self::Finish {
        StreamWriter::finish(self)
    }

    fn reset(&mut self, code: ResetCode) {
        StreamWriter::reset(self, code);
    }
}
