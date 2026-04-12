use std::collections::HashMap;

use super::{
    request::{handle_request, RequestHandler},
    Router, RouterConfig, RpcStream,
};
use crate::{request::Request as RequestRpc, router::RouteFn, RouteId};

pub struct RouterBuilder<S, St> {
    config: RouterConfig,
    routes: HashMap<RouteId, RouteFn<S, St>>,
}

impl<S, St> Default for RouterBuilder<S, St> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, St> RouterBuilder<S, St> {
    pub fn new() -> Self {
        Self {
            config: RouterConfig::default(),
            routes: std::collections::HashMap::new(),
        }
    }

    pub fn config(mut self, config: RouterConfig) -> Self {
        self.config = config;
        self
    }

    pub fn max_request_bytes(mut self, max_request_bytes: usize) -> Self {
        self.config.max_request_bytes = max_request_bytes;
        self
    }

    pub fn request<M>(self) -> Self
    where
        M: RequestRpc,
        S: RequestHandler<M>,
        St: RpcStream + 'static,
    {
        self.add_route(M::METHOD, handle_request::<S, M, St>)
    }

    pub fn build(mut self, state: S) -> Router<S, St> {
        self.routes.shrink_to_fit();
        Router {
            config: self.config,
            state,
            routes: self.routes,
        }
    }

    fn add_route(mut self, route_id: crate::RouteId, route: super::RouteFn<S, St>) -> Self {
        if self.routes.insert(route_id, route).is_some() {
            panic!("duplicate rpc route {}", route_id.into_inner());
        }
        self
    }
}
