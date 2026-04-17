use std::collections::HashMap;

use super::{
    LocalSpawn, LocalSpawner, RouteFn, Router, RouterConfig, RpcStream, SendSpawn, SendSpawner,
    Spawner,
};
use crate::{
    download::{
        server::{handle_download_inner, DownloadHandler},
        Download as DownloadRpc,
    },
    notification::{
        server::{handle_notification_inner, NotificationHandler},
        Notification as NotificationRpc,
    },
    progress::{
        server::{handle_progress_inner, ProgressHandler},
        Progress as ProgressRpc,
    },
    request::{
        server::{handle_request_inner, RequestHandler},
        Request as RequestRpc,
    },
    subscription::{
        server::{handle_subscription_inner, SubscriptionHandler},
        Subscription as SubscriptionRpc,
    },
    RouteId,
};

pub struct RouterBuilder<S, St, Sp>
where
    Sp: Spawner,
{
    config: RouterConfig,
    spawner: Sp,
    routes: HashMap<RouteId, RouteFn<S, St, Sp>>,
}

impl<S, St, Sp> RouterBuilder<S, St, Sp>
where
    Sp: Spawner,
{
    pub fn new(spawner: Sp) -> Self {
        Self {
            config: RouterConfig::default(),
            spawner,
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

    pub fn build(mut self, state: S) -> Router<S, St, Sp> {
        self.routes.shrink_to_fit();
        Router {
            config: self.config,
            state,
            spawner: self.spawner,
            routes: self.routes,
        }
    }

    fn add_route(mut self, route_id: crate::RouteId, route: RouteFn<S, St, Sp>) -> Self {
        if self.routes.insert(route_id, route).is_some() {
            panic!("duplicate rpc route {}", route_id.into_inner());
        }
        self
    }
}

impl<S, St> RouterBuilder<S, St, LocalSpawn>
where
    St: RpcStream + 'static,
{
    pub fn request<M>(self) -> Self
    where
        M: RequestRpc + 'static,
        S: RequestHandler<M, St> + 'static,
    {
        self.add_route(M::ROUTE, |spawner, state, config, stream| {
            let (reader, writer) = stream.split();
            spawner.spawn(handle_request_inner::<S, M, St>(
                state, config, reader, writer,
            ))
        })
    }

    pub fn notification<M>(self) -> Self
    where
        M: NotificationRpc + 'static,
        S: NotificationHandler<M, St> + 'static,
    {
        self.add_route(M::ROUTE, |spawner, state, config, stream| {
            let (reader, writer) = stream.split();
            spawner.spawn(handle_notification_inner::<S, M, St>(
                state, config, reader, writer,
            ))
        })
    }

    pub fn download<M>(self) -> Self
    where
        M: DownloadRpc + 'static,
        S: DownloadHandler<M, St> + 'static,
    {
        self.add_route(M::ROUTE, |spawner, state, config, stream| {
            let (reader, writer) = stream.split();
            spawner.spawn(handle_download_inner::<S, M, St>(
                state, config, reader, writer,
            ))
        })
    }

    pub fn subscription<M>(self) -> Self
    where
        M: SubscriptionRpc + 'static,
        S: SubscriptionHandler<M, St> + 'static,
    {
        self.add_route(M::ROUTE, |spawner, state, config, stream| {
            let (reader, writer) = stream.split();
            spawner.spawn(handle_subscription_inner::<S, M, St>(
                state, config, reader, writer,
            ))
        })
    }

    pub fn progress<M>(self) -> Self
    where
        M: ProgressRpc + 'static,
        S: ProgressHandler<M, St> + 'static,
    {
        self.add_route(M::ROUTE, |spawner, state, config, stream| {
            let (reader, writer) = stream.split();
            spawner.spawn(handle_progress_inner::<S, M, St>(
                state, config, reader, writer,
            ))
        })
    }
}

impl<S, St> RouterBuilder<S, St, SendSpawn>
where
    St: RpcStream + 'static,
{
    pub fn request<M>(self) -> Self
    where
        M: RequestRpc + 'static,
        M::Request: Send + 'static,
        S: RequestHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        self.add_route(M::ROUTE, |spawner, state, config, stream| {
            let (reader, writer) = stream.split();
            spawner.spawn(handle_request_inner::<S, M, St>(
                state, config, reader, writer,
            ))
        })
    }

    pub fn notification<M>(self) -> Self
    where
        M: NotificationRpc + 'static,
        M::Payload: Send + 'static,
        S: NotificationHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        self.add_route(M::ROUTE, |spawner, state, config, stream| {
            let (reader, writer) = stream.split();
            spawner.spawn(handle_notification_inner::<S, M, St>(
                state, config, reader, writer,
            ))
        })
    }

    pub fn download<M>(self) -> Self
    where
        M: DownloadRpc + 'static,
        M::Request: Send + 'static,
        S: DownloadHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        self.add_route(M::ROUTE, |spawner, state, config, stream| {
            let (reader, writer) = stream.split();
            spawner.spawn(handle_download_inner::<S, M, St>(
                state, config, reader, writer,
            ))
        })
    }

    pub fn subscription<M>(self) -> Self
    where
        M: SubscriptionRpc + 'static,
        M::Request: Send + 'static,
        S: SubscriptionHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        self.add_route(M::ROUTE, |spawner, state, config, stream| {
            let (reader, writer) = stream.split();
            spawner.spawn(handle_subscription_inner::<S, M, St>(
                state, config, reader, writer,
            ))
        })
    }

    pub fn progress<M>(self) -> Self
    where
        M: ProgressRpc + 'static,
        M::Request: Send + 'static,
        S: ProgressHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        self.add_route(M::ROUTE, |spawner, state, config, stream| {
            let (reader, writer) = stream.split();
            spawner.spawn(handle_progress_inner::<S, M, St>(
                state, config, reader, writer,
            ))
        })
    }
}
