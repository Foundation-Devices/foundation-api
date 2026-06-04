use std::task::{Context, Poll};

use bytes::Bytes;
use ql_rpc::{RouteId, RpcRead, RpcStream, RpcWrite, StreamCloseCode, StreamError};
use ql_wire::{RouteId as WireRouteId, StreamCloseCode as WireStreamCloseCode};

use crate::{QlStream, QlStreamError, StreamReader, StreamWriter};

impl RpcStream for QlStream {
    type Error = QlStreamError;
    type Reader = StreamReader;
    type Writer = StreamWriter;

    fn route_id(&self) -> Option<RouteId> {
        let route_id = u32::try_from(self.route_id.into_inner()).ok()?;
        Some(RouteId::from_u32(route_id))
    }

    fn split(self) -> (Self::Reader, Self::Writer) {
        (self.reader, self.writer)
    }
}

impl RpcRead for StreamReader {
    type Error = QlStreamError;

    fn poll_read(
        &mut self,
        max_len: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, QlStreamError>> {
        StreamReader::poll_read(self, max_len, cx)
    }

    fn close(self, code: StreamCloseCode) {
        StreamReader::close(self, to_wire_close_code(code));
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

    fn close(self, code: StreamCloseCode) {
        StreamWriter::close(self, to_wire_close_code(code));
    }
}

pub(super) fn to_wire_route_id(route_id: RouteId) -> WireRouteId {
    WireRouteId::from_u32(route_id.into_inner())
}

pub(super) fn to_wire_close_code(code: StreamCloseCode) -> WireStreamCloseCode {
    WireStreamCloseCode(code.into_inner())
}

impl From<StreamCloseCode> for QlStreamError {
    fn from(code: StreamCloseCode) -> Self {
        Self::StreamClosed {
            code: WireStreamCloseCode(code.into_inner()),
        }
    }
}

impl StreamError for QlStreamError {
    fn close_code(&self) -> Option<StreamCloseCode> {
        match self {
            QlStreamError::StreamClosed { code } => Some(StreamCloseCode(code.0)),
            QlStreamError::NoSession => None,
        }
    }
}
