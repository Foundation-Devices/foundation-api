use std::{collections::HashMap, future::Future, pin::Pin};

use crate::{RouteId, StreamCloseCode};

mod builder;
mod config;
mod request;
mod stream;

pub use self::{
    builder::RouterBuilder,
    config::RouterConfig,
    request::RequestHandler,
    stream::{RpcRead, RpcStream, RpcWrite},
};

type RouteFuture<'a> = Pin<Box<dyn Future<Output = ()> + 'a>>;
type RouteFn<S, St> = for<'a> fn(&'a S, RouterConfig, St) -> RouteFuture<'a>;

pub struct Router<S, St> {
    config: RouterConfig,
    state: S,
    routes: HashMap<RouteId, RouteFn<S, St>>,
}

impl<S, St> Router<S, St>
where
    St: RpcStream,
{
    pub fn builder() -> RouterBuilder<S, St> {
        RouterBuilder::<S, St>::new()
    }

    pub async fn handle(&self, stream: St) {
        let Some(route_id) = stream.route_id() else {
            stream::close_stream(stream, StreamCloseCode::UNKNOWN_ROUTE);
            return;
        };
        let Some(route) = self.routes.get(&route_id).copied() else {
            stream::close_stream(stream, StreamCloseCode::UNKNOWN_ROUTE);
            return;
        };
        route(&self.state, self.config, stream).await;
    }
}
