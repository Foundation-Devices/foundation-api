use std::collections::HashMap;

use crate::{RouteId, StreamCloseCode};

mod builder;
mod config;
mod mode;
mod request;
mod stream;

pub use self::{
    builder::RouterBuilder,
    config::RouterConfig,
    mode::*,
    request::{RequestHandler, Response},
    stream::{RpcRead, RpcStream, RpcWrite},
};

pub struct Router<S, St, Mode = LocalMode>
where
    Mode: RouteMode,
{
    config: RouterConfig,
    state: S,
    routes: HashMap<RouteId, RouteFn<S, St, Mode>>,
}

impl<S, St, Mode> Router<S, St, Mode>
where
    S: Clone + 'static,
    St: RpcStream,
    Mode: RouteMode,
{
    pub fn builder() -> RouterBuilder<S, St, Mode> {
        RouterBuilder::<S, St, Mode>::new()
    }

    pub fn handle(&self, stream: St) -> Option<(RouteId, Mode::RouteFuture)> {
        let route_id = stream.route_id()?;
        let Some(route) = self.routes.get(&route_id).copied() else {
            stream::close_stream(stream, StreamCloseCode::UNKNOWN_ROUTE);
            return None;
        };
        Some((route_id, route(self.state.clone(), self.config, stream)))
    }
}
