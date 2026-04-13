use std::collections::HashMap;

use super::{
    request::{RequestHandler, RequestRouteMode},
    subscription::{SubscriptionHandler, SubscriptionRouteMode},
    LocalMode, RouteMode, Router, RouterConfig, RpcStream,
};
use crate::{
    request::Request as RequestRpc, router::RouteFn, subscription::Subscription as SubscriptionRpc,
    RouteId,
};

pub struct RouterBuilder<S, St, Mode = LocalMode>
where
    Mode: RouteMode,
{
    config: RouterConfig,
    routes: HashMap<RouteId, RouteFn<S, St, Mode>>,
}

impl<S, St, Mode> Default for RouterBuilder<S, St, Mode>
where
    Mode: RouteMode,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S, St, Mode> RouterBuilder<S, St, Mode>
where
    Mode: RouteMode,
{
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

    pub fn build(mut self, state: S) -> Router<S, St, Mode> {
        self.routes.shrink_to_fit();
        Router {
            config: self.config,
            state,
            routes: self.routes,
        }
    }

    fn add_route(mut self, route_id: crate::RouteId, route: super::RouteFn<S, St, Mode>) -> Self {
        if self.routes.insert(route_id, route).is_some() {
            panic!("duplicate rpc route {}", route_id.into_inner());
        }
        self
    }
}

impl<S, St, Mode> RouterBuilder<S, St, Mode>
where
    Mode: RouteMode,
{
    pub fn request<M>(self) -> Self
    where
        M: RequestRpc + 'static,
        S: RequestHandler<M, St> + 'static,
        St: RpcStream + 'static,
        Mode: RequestRouteMode<S, M, St>,
    {
        self.add_route(
            M::ROUTE,
            <Mode as RequestRouteMode<S, M, St>>::handle_request,
        )
    }

    pub fn subscription<M>(self) -> Self
    where
        M: SubscriptionRpc + 'static,
        S: SubscriptionHandler<M, St> + 'static,
        St: RpcStream + 'static,
        Mode: SubscriptionRouteMode<S, M, St>,
    {
        self.add_route(
            M::ROUTE,
            <Mode as SubscriptionRouteMode<S, M, St>>::handle_subscription,
        )
    }
}
