use crate::{RouteId, StreamCloseCode};

mod builder;
mod config;
mod mode;

pub use self::{
    builder::{LocalRoutes, RouterBuilder, SendRoutes},
    config::RouterConfig,
    mode::*,
};
use crate::{close_stream, RpcStream};
pub use crate::{
    download::{DownloadHandler, DownloadHandlerLocal, DownloadStart, DownloadWriter},
    duplex::{DuplexHandler, DuplexHandlerLocal, DuplexPeer},
    notification::{NotificationHandler, NotificationHandlerLocal},
    progress::{ProgressHandler, ProgressHandlerLocal, ProgressResponder},
    request::{RequestHandler, RequestHandlerLocal, Response},
    subscription::{SubscriptionHandler, SubscriptionHandlerLocal, SubscriptionResponder},
    upload::{UploadHandler, UploadHandlerLocal, UploadReader, UploadResponder},
};

pub struct Router<S, St, Sp>
where
    Sp: Spawner,
{
    config: RouterConfig,
    state: S,
    spawner: Sp,
    routes: Vec<RouteEntry<S, St, Sp>>,
}

struct RouteEntry<S, St, Sp>
where
    Sp: Spawner,
{
    route_id: RouteId,
    route: RouteFn<S, St, Sp>,
}

impl<S, St, Sp> RouteEntry<S, St, Sp>
where
    Sp: Spawner,
{
    fn new(route_id: RouteId, route: RouteFn<S, St, Sp>) -> Self {
        Self { route_id, route }
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

    pub fn handle(&self, stream: St) -> Option<(RouteId, Sp::Handle)> {
        let route_id = stream.route_id()?;
        let Ok(index) = self
            .routes
            .binary_search_by_key(&route_id, |entry| entry.route_id)
        else {
            close_stream(stream, StreamCloseCode::UNKNOWN_ROUTE);
            return None;
        };
        let route = self.routes[index].route;
        Some((
            route_id,
            route(&self.spawner, self.state.clone(), self.config, stream),
        ))
    }

    pub fn route_ids(&self) -> impl ExactSizeIterator<Item = RouteId> + '_ {
        self.routes.iter().map(|entry| entry.route_id)
    }
}
