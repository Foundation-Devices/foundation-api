use std::marker::PhantomData;

use super::*;
use crate::{
    download::*, duplex::*, notification::*, progress::*, request::*, subscription::*, upload::*,
    Route,
};

pub struct LocalRoutes;
pub struct SendRoutes;

pub struct RouterBuilder<K, S, St, Sp, Mode>
where
    K: RpcRouteKey,
    Sp: Spawner,
{
    config: RouterConfig,
    spawner: Sp,
    routes: Vec<RouteEntry<K, S, St, Sp>>,
    marker: PhantomData<fn() -> Mode>,
}

impl<K, S, St, Sp, Mode> RouterBuilder<K, S, St, Sp, Mode>
where
    K: RpcRouteKey,
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

    pub fn build(mut self, state: S) -> Router<K, S, St, Sp> {
        self.routes.sort_by_key(|entry| entry.key.clone());
        self.routes.shrink_to_fit();
        Router {
            config: self.config,
            state,
            spawner: self.spawner,
            routes: self.routes,
        }
    }

    fn add_route(mut self, key: K, route: RouteFn<S, St, Sp>) -> Self {
        if self.routes.iter().any(|entry| entry.key == key) {
            panic!("duplicate rpc route {key:?}");
        }
        self.routes.push(RouteEntry::new(key, route));
        self
    }
}

impl<K, S, St, Sp> RouterBuilder<K, S, St, Sp, LocalRoutes>
where
    K: RpcRouteKey,
    Sp: LocalSpawner,
    St: RpcStream + 'static,
{
    pub fn request<M>(self) -> Self
    where
        M: Request<Key = K> + 'static,
        S: RequestHandlerLocal<M, St> + 'static,
    {
        add_route!(self, M, handle_request, S::handle, S::handle_error)
    }

    pub fn notification<M>(self) -> Self
    where
        M: Notification<Key = K> + 'static,
        S: NotificationHandlerLocal<M, St> + 'static,
    {
        add_route!(self, M, handle_notification, S::handle, S::handle_error)
    }

    pub fn duplex<M>(self) -> Self
    where
        M: Duplex<Key = K> + 'static,
        S: DuplexHandlerLocal<M, St> + 'static,
    {
        add_route!(self, M, handle_duplex, S::handle)
    }

    pub fn download<M>(self) -> Self
    where
        M: Download<Key = K> + 'static,
        S: DownloadHandlerLocal<M, St> + 'static,
    {
        add_route!(self, M, handle_download, S::handle, S::handle_error)
    }

    pub fn subscription<M>(self) -> Self
    where
        M: Subscription<Key = K> + 'static,
        S: SubscriptionHandlerLocal<M, St> + 'static,
    {
        add_route!(self, M, handle_subscription, S::handle, S::handle_error)
    }

    pub fn progress<M>(self) -> Self
    where
        M: Progress<Key = K> + 'static,
        S: ProgressHandlerLocal<M, St> + 'static,
    {
        add_route!(self, M, handle_progress, S::handle, S::handle_error)
    }

    pub fn upload<M>(self) -> Self
    where
        M: Upload<Key = K> + 'static,
        S: UploadHandlerLocal<M, St> + 'static,
    {
        add_route!(
            self,
            M,
            handle_upload::<M, _, _, _, _, _>,
            S::handle,
            S::handle_error
        )
    }
}

impl<K, S, St, Sp> RouterBuilder<K, S, St, Sp, SendRoutes>
where
    K: RpcRouteKey,
    Sp: SendSpawner + Send,
    St: RpcStream + 'static,
{
    pub fn request<M>(self) -> Self
    where
        M: Request<Key = K> + 'static,
        M::Request: Send + 'static,
        S: RequestHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        add_route!(self, M, handle_request, S::handle, S::handle_error)
    }

    pub fn notification<M>(self) -> Self
    where
        M: Notification<Key = K> + 'static,
        M::Payload: Send + 'static,
        S: NotificationHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        add_route!(self, M, handle_notification, S::handle, S::handle_error)
    }

    pub fn duplex<M>(self) -> Self
    where
        M: Duplex<Key = K> + 'static,
        M::InitiatorEvent: Send + 'static,
        M::ResponderEvent: Send + 'static,
        S: DuplexHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        add_route!(self, M, handle_duplex, S::handle)
    }

    pub fn download<M>(self) -> Self
    where
        M: Download<Key = K> + 'static,
        M::Request: Send + 'static,
        S: DownloadHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        add_route!(self, M, handle_download, S::handle, S::handle_error)
    }

    pub fn subscription<M>(self) -> Self
    where
        M: Subscription<Key = K> + 'static,
        M::Request: Send + 'static,
        S: SubscriptionHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        add_route!(self, M, handle_subscription, S::handle, S::handle_error)
    }

    pub fn progress<M>(self) -> Self
    where
        M: Progress<Key = K> + 'static,
        M::Request: Send + 'static,
        S: ProgressHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        add_route!(self, M, handle_progress, S::handle, S::handle_error)
    }

    pub fn upload<M>(self) -> Self
    where
        M: Upload<Key = K> + 'static,
        M::Request: Send + 'static,
        S: UploadHandler<M, St> + Send + 'static,
        St::Reader: Send + 'static,
        St::Writer: Send + 'static,
    {
        add_route!(
            self,
            M,
            handle_upload::<M, _, _, _, _, _>,
            S::handle,
            S::handle_error
        )
    }
}

macro_rules! add_route {
    ($builder:expr, $rpc:ty, $handler:path, $($arg:path),+ $(,)?) => {
        $builder.add_route(
            <$rpc as Route>::key(),
            |spawner, state, context, config, stream| {
                spawner.spawn($handler(
                    state,
                    context,
                    config,
                    stream,
                    $($arg),+
                ))
            },
        )
    };
}

use add_route;
