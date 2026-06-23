use std::task::{Context, Poll};

use bytes::Bytes;
use ql_rpc::{ResetCode, RouteId, RpcRead, RpcStream, RpcWrite, ServiceId};

use crate::{QlStream, QlStreamError, StreamReader, StreamWriter};

impl RpcStream for QlStream {
    type Error = QlStreamError;
    type Reader = StreamReader;
    type Writer = StreamWriter;

    fn service_id(&self) -> Option<ServiceId> {
        Some(self.service_id)
    }

    fn route_id(&self) -> Option<RouteId> {
        Some(self.route_id)
    }

    fn split(self) -> (Self::Reader, Self::Writer) {
        (self.reader, self.writer)
    }
}

impl RpcRead for StreamReader {
    type Error = QlStreamError;

    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, QlStreamError>> {
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
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), QlStreamError>> {
        StreamWriter::poll_write(self, bytes, cx)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), QlStreamError>> {
        StreamWriter::poll_finish(self, cx)
    }

    fn reset(self, code: ResetCode) {
        StreamWriter::reset(self, code);
    }
}
