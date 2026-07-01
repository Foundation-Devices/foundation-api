use ql_common::{ResetCode, RouteId, ServiceId, StreamId, StreamInfo, QID};

mod builder;
mod config;
mod mode;

pub use self::{builder::*, config::*, mode::*};
use crate::{decode_stream_header, RpcRead, RpcStream, RpcWrite};

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

    pub fn handle(&self, info: StreamInfo, stream: St) -> Option<Sp::Handle> {
        let StreamInfo {
            qid,
            stream_id,
            header,
        } = info;
        let context = Context { qid, stream_id };
        let Some(key) = decode_stream_header(&header) else {
            let (reader, writer) = stream.split();
            reader.reset(ResetCode::PROTOCOL);
            writer.reset(ResetCode::PROTOCOL);
            return None;
        };
        let Ok(index) = self.routes.binary_search_by_key(&key, |entry| entry.key) else {
            let (reader, writer) = stream.split();
            reader.reset(ResetCode::UNKNOWN_ROUTE);
            writer.reset(ResetCode::UNKNOWN_ROUTE);
            return None;
        };
        let route = self.routes[index].route;
        Some(route(
            &self.spawner,
            self.state.clone(),
            context,
            self.config,
            stream,
        ))
    }

    pub fn route_ids(&self) -> impl ExactSizeIterator<Item = RouteId> + '_ {
        self.routes.iter().map(|entry| entry.key.route_id)
    }

    pub fn route_keys(&self) -> impl ExactSizeIterator<Item = RouteKey> + '_ {
        self.routes.iter().map(|entry| entry.key)
    }
}
