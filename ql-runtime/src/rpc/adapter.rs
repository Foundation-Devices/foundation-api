use std::task::{Context, Poll};

use bytes::Bytes;
pub use ql_rpc::{
    LocalMode, RequestHandler, Response, RouteId, RouterConfig, SendMode, StreamCloseCode,
    SubscriptionHandler, SubscriptionResponder,
};
use ql_rpc::{RpcRead, RpcStream, RpcWrite};
use ql_wire::{RouteId as WireRouteId, StreamCloseCode as WireStreamCloseCode};

use crate::{ByteReader, ByteWriter, QlStream, QlStreamError};

pub type Router<S> = ql_rpc::Router<S, QlStream>;
pub type RouterBuilder<S> = ql_rpc::RouterBuilder<S, QlStream>;
pub type SendRouter<S> = ql_rpc::Router<S, QlStream, SendMode>;
pub type SendRouterBuilder<S> = ql_rpc::RouterBuilder<S, QlStream, SendMode>;

impl RpcStream for QlStream {
    type Reader = ByteReader;
    type Writer = ByteWriter;

    fn route_id(&self) -> Option<RouteId> {
        let route_id = u32::try_from(self.route_id.into_inner()).ok()?;
        Some(RouteId::from_u32(route_id))
    }

    fn split(self) -> (Self::Reader, Self::Writer) {
        (self.reader, self.writer)
    }
}

impl RpcRead for ByteReader {
    fn poll_read(
        &mut self,
        max_len: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamCloseCode>> {
        ByteReader::poll_read(self, max_len, cx).map(|result| result.map_err(from_stream_error))
    }

    fn close(self, code: StreamCloseCode) {
        ByteReader::close(self, to_wire_close_code(code));
    }
}

impl RpcWrite for ByteWriter {
    fn poll_write(
        &mut self,
        bytes: &mut Bytes,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), StreamCloseCode>> {
        ByteWriter::poll_write(self, bytes, cx).map(|result| result.map_err(from_stream_error))
    }

    fn finish(self) {
        ByteWriter::finish(self);
    }

    fn close(self, code: StreamCloseCode) {
        ByteWriter::close(self, to_wire_close_code(code));
    }
}

pub(super) fn to_wire_route_id(route_id: RouteId) -> WireRouteId {
    WireRouteId::from_u32(route_id.into_inner())
}

pub(super) fn to_wire_close_code(code: StreamCloseCode) -> WireStreamCloseCode {
    WireStreamCloseCode(code.into_inner())
}

fn from_stream_error(error: QlStreamError) -> StreamCloseCode {
    let code = match error {
        QlStreamError::StreamClosed { code } => code,
        QlStreamError::NoSession => WireStreamCloseCode::CANCELLED,
    };
    StreamCloseCode(code.0)
}
