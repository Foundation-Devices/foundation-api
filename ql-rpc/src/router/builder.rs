use std::marker::PhantomData;

use super::{
    LocalSpawner, RouteEntry, RouteFn, Router, RouterConfig, RpcStream, SendSpawner, Spawner,
};
use crate::{
    download::{server::*, Download as DownloadRpc},
    duplex::{server::*, Duplex as DuplexRpc},
    notification::{server::*, Notification as NotificationRpc},
    progress::{server::*, Progress as ProgressRpc},
    request::{server::*, Request as RequestRpc},
    subscription::{server::*, Subscription as SubscriptionRpc},
    upload::{server::*, Upload as UploadRpc},
    RouteKey,
};

pub struct LocalRoutes;
pub struct SendRoutes;

pub struct RouterBuilder<S, St, Sp, Mode>
where
    Sp: Spawner,
{
    config: RouterConfig,
    spawner: Sp,
    routes: Vec<RouteEntry<S, St, Sp>>,
    marker: PhantomData<fn() -> Mode>,
}

impl<S, St, Sp, Mode> RouterBuilder<S, St, Sp, Mode>
where
    Sp: Spawner,
{
    pub(crate) fn new(spawner: Sp) -> Self {
        Self {
            config: RouterConfig::default(),
            spawner,
            routes: Vec::new(),
            marker: PhantomData,
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
        self.routes.sort_by_key(|entry| entry.key);
        self.routes.shrink_to_fit();
        Router {
            config: self.config,
            state,
            spawner: self.spawner,
            routes: self.routes,
        }
    }

    fn add_route(mut self, key: RouteKey, route: RouteFn<S, St, Sp>) -> Self {
        if self.routes.iter().any(|entry| entry.key == key) {
            panic!(
                "duplicate rpc route {} for service {:?}",
                key.route_id.0.into_inner(),
                key.service_id.0
            );
        }
        self.routes.push(RouteEntry::new(key, route));
        self
    }
}

impl<S, St, Sp> RouterBuilder<S, St, Sp, LocalRoutes>
where
    Sp: LocalSpawner,
    St: RpcStream + 'static,
{
    pub fn request<M>(self) -> Self
    where
        M: RequestRpc + 'static,
        S: RequestHandlerLocal<M, St> + 'static,
    {
        self.add_route(
            RouteKey::new::<M>(),
            |spawner, state, context, config, stream| {
                let (reader, writer) = stream.split();
                spawner.spawn(handle_request_inner::<S, M, St, _, _, _>(
                    state,
                    context,
                    config,
                    reader,
                    writer,
                    S::handle,
                    S::handle_error,
                ))
            },
        )
    }

    pub fn notification<M>(self) -> Self
    where
        M: NotificationRpc + 'static,
        S: NotificationHandlerLocal<M, St> + 'static,
    {
        self.add_route(
            RouteKey::new::<M>(),
            |spawner, state, context, config, stream| {
                let (reader, writer) = stream.split();
                spawner.spawn(handle_notification_inner::<S, M, St, _, _, _>(
                    state,
                    context,
                    config,
                    reader,
                    writer,
                    S::handle,
                    S::handle_error,
                ))
            },
        )
    }

    pub fn duplex<M>(self) -> Self
    where
        M: DuplexRpc + 'static,
        S: DuplexHandlerLocal<M, St> + 'static,
    {
        self.add_route(
            RouteKey::new::<M>(),
            |spawner, state, context, config, stream| {
                let (reader, writer) = stream.split();
                spawner.spawn(handle_duplex_inner::<S, M, St, _, _>(
                    state,
                    context,
                    config,
                    reader,
                    writer,
                    S::handle,
                ))
            },
        )
    }

    pub fn download<M>(self) -> Self
    where
        M: DownloadRpc + 'static,
        S: DownloadHandlerLocal<M, St> + 'static,
    {
        self.add_route(
            RouteKey::new::<M>(),
            |spawner, state, context, config, stream| {
                let (reader, writer) = stream.split();
                spawner.spawn(handle_download_inner::<S, M, St, _, _, _>(
                    state,
                    context,
                    config,
                    reader,
                    writer,
                    S::handle,
                    S::handle_error,
                ))
            },
        )
    }

    pub fn subscription<M>(self) -> Self
    where
        M: SubscriptionRpc + 'static,
        S: SubscriptionHandlerLocal<M, St> + 'static,
    {
        self.add_route(
            RouteKey::new::<M>(),
            |spawner, state, context, config, stream| {
                let (reader, writer) = stream.split();
                spawner.spawn(handle_subscription_inner::<S, M, St, _, _, _>(
                    state,
                    context,
                    config,
                    reader,
                    writer,
                    S::handle,
                    S::handle_error,
                ))
            },
        )
    }

    pub fn progress<M>(self) -> Self
    where
        M: ProgressRpc + 'static,
        S: ProgressHandlerLocal<M, St> + 'static,
    {
        self.add_route(
            RouteKey::new::<M>(),
            |spawner, state, context, config, stream| {
                let (reader, writer) = stream.split();
                spawner.spawn(handle_progress_inner::<S, M, St, _, _, _>(
                    state,
                    context,
                    config,
                    reader,
                    writer,
                    S::handle,
                    S::handle_error,
                ))
            },
        )
    }

    pub fn upload<M>(self) -> Self
    where
        M: UploadRpc + 'static,
        S: UploadHandlerLocal<M, St> + 'static,
    {
        self.add_route(
            RouteKey::new::<M>(),
            |spawner, state, context, config, stream| {
                let (reader, writer) = stream.split();
                spawner.spawn(handle_upload_inner::<S, M, St, _, _, _>(
                    state,
                    context,
                    config,
                    reader,
                    writer,
                    S::handle,
                    S::handle_error,
                ))
            },
        )
    }
}

impl<S, St, Sp> RouterBuilder<S, St, Sp, SendRoutes>
where
    Sp: SendSpawner + Send,
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
        self.add_route(
            RouteKey::new::<M>(),
            |spawner, state, context, config, stream| {
                let (reader, writer) = stream.split();
                spawner.spawn(handle_request_inner::<S, M, St, _, _, _>(
                    state,
                    context,
                    config,
                    reader,
                    writer,
                    S::handle,
                    S::handle_error,
                ))
            },
        )
    }

    pub fn notification<M>(self) -> Self
    where
        M: NotificationRpc + 'static,
        M::Payload: Send + 'static,
        S: NotificationHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        self.add_route(
            RouteKey::new::<M>(),
            |spawner, state, context, config, stream| {
                let (reader, writer) = stream.split();
                spawner.spawn(handle_notification_inner::<S, M, St, _, _, _>(
                    state,
                    context,
                    config,
                    reader,
                    writer,
                    S::handle,
                    S::handle_error,
                ))
            },
        )
    }

    pub fn duplex<M>(self) -> Self
    where
        M: DuplexRpc + 'static,
        M::InitiatorEvent: Send + 'static,
        M::ResponderEvent: Send + 'static,
        S: DuplexHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        self.add_route(
            RouteKey::new::<M>(),
            |spawner, state, context, config, stream| {
                let (reader, writer) = stream.split();
                spawner.spawn(handle_duplex_inner::<S, M, St, _, _>(
                    state,
                    context,
                    config,
                    reader,
                    writer,
                    S::handle,
                ))
            },
        )
    }

    pub fn download<M>(self) -> Self
    where
        M: DownloadRpc + 'static,
        M::Request: Send + 'static,
        S: DownloadHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        self.add_route(
            RouteKey::new::<M>(),
            |spawner, state, context, config, stream| {
                let (reader, writer) = stream.split();
                spawner.spawn(handle_download_inner::<S, M, St, _, _, _>(
                    state,
                    context,
                    config,
                    reader,
                    writer,
                    S::handle,
                    S::handle_error,
                ))
            },
        )
    }

    pub fn subscription<M>(self) -> Self
    where
        M: SubscriptionRpc + 'static,
        M::Request: Send + 'static,
        S: SubscriptionHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        self.add_route(
            RouteKey::new::<M>(),
            |spawner, state, context, config, stream| {
                let (reader, writer) = stream.split();
                spawner.spawn(handle_subscription_inner::<S, M, St, _, _, _>(
                    state,
                    context,
                    config,
                    reader,
                    writer,
                    S::handle,
                    S::handle_error,
                ))
            },
        )
    }

    pub fn progress<M>(self) -> Self
    where
        M: ProgressRpc + 'static,
        M::Request: Send + 'static,
        S: ProgressHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        self.add_route(
            RouteKey::new::<M>(),
            |spawner, state, context, config, stream| {
                let (reader, writer) = stream.split();
                spawner.spawn(handle_progress_inner::<S, M, St, _, _, _>(
                    state,
                    context,
                    config,
                    reader,
                    writer,
                    S::handle,
                    S::handle_error,
                ))
            },
        )
    }

    pub fn upload<M>(self) -> Self
    where
        M: UploadRpc + 'static,
        M::Request: Send + 'static,
        S: UploadHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        self.add_route(
            RouteKey::new::<M>(),
            |spawner, state, context, config, stream| {
                let (reader, writer) = stream.split();
                spawner.spawn(handle_upload_inner::<S, M, St, _, _, _>(
                    state,
                    context,
                    config,
                    reader,
                    writer,
                    S::handle,
                    S::handle_error,
                ))
            },
        )
    }
}
