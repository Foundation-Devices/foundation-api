use crate::{ResetCode, RouteId, ServiceId, StreamId, StreamInfo, QID};

mod builder;
mod config;
mod mode;

pub use self::{
    builder::{LocalRoutes, RouterBuilder, SendRoutes},
    config::RouterConfig,
    mode::*,
};
pub use crate::{
    download::{DownloadHandler, DownloadHandlerLocal, DownloadStart, DownloadWriter},
    duplex::{DuplexHandler, DuplexHandlerLocal, DuplexPeer},
    notification::{NotificationHandler, NotificationHandlerLocal},
    progress::{ProgressHandler, ProgressHandlerLocal, ProgressResponder},
    request::{RequestHandler, RequestHandlerLocal, Response},
    subscription::{SubscriptionHandler, SubscriptionHandlerLocal, SubscriptionResponder},
    upload::{UploadHandler, UploadHandlerLocal, UploadReader, UploadResponder},
};
use crate::{reset_stream, RpcStream};

pub struct Router<S, St, Sp>
where
    Sp: Spawner,
{
    config: RouterConfig,
    state: S,
    spawner: Sp,
    routes: Vec<RouteEntry<S, St, Sp>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Context {
    pub qid: QID,
    pub stream_id: StreamId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteKey {
    pub service_id: ServiceId,
    pub route_id: RouteId,
}

impl RouteKey {
    pub const fn new<R: crate::Route>() -> Self {
        Self {
            service_id: R::SERVICE,
            route_id: R::ROUTE,
        }
    }
}

struct RouteEntry<S, St, Sp>
where
    Sp: Spawner,
{
    key: RouteKey,
    route: RouteFn<S, St, Sp>,
}

impl<S, St, Sp> RouteEntry<S, St, Sp>
where
    Sp: Spawner,
{
    fn new(key: RouteKey, route: RouteFn<S, St, Sp>) -> Self {
        Self { key, route }
    }
}

impl<S, St, Sp> Router<S, St, Sp>
where
    S: Clone + 'static,
    St: RpcStream,
    Sp: Spawner,
{
    pub fn builder_local(spawner: Sp) -> RouterBuilder<S, St, Sp, LocalRoutes>
    where
        Sp: LocalSpawner,
    {
        RouterBuilder::<S, St, Sp, LocalRoutes>::new(spawner)
    }

    pub fn builder_send(spawner: Sp) -> RouterBuilder<S, St, Sp, SendRoutes>
    where
        Sp: SendSpawner,
    {
        RouterBuilder::<S, St, Sp, SendRoutes>::new(spawner)
    }

    pub fn handle(&self, info: StreamInfo, stream: St) -> Option<(RouteId, Sp::Handle)> {
        let StreamInfo {
            qid,
            stream_id,
            service_id,
            route_id,
        } = info;
        let context = Context { qid, stream_id };
        let key = RouteKey {
            service_id,
            route_id,
        };
        let Ok(index) = self.routes.binary_search_by_key(&key, |entry| entry.key) else {
            reset_stream(stream, ResetCode::UNKNOWN_ROUTE);
            return None;
        };
        let route = self.routes[index].route;
        Some((
            route_id,
            route(
                &self.spawner,
                self.state.clone(),
                context,
                self.config,
                stream,
            ),
        ))
    }

    pub fn route_ids(&self) -> impl ExactSizeIterator<Item = RouteId> + '_ {
        self.routes.iter().map(|entry| entry.key.route_id)
    }

    pub fn route_keys(&self) -> impl ExactSizeIterator<Item = RouteKey> + '_ {
        self.routes.iter().map(|entry| entry.key)
    }
}
