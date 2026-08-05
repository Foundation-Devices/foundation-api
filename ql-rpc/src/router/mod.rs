use ql_common::{ResetCode, StreamId, StreamInfo, QID};

mod builder;
mod config;
mod mode;

pub use self::{builder::*, config::*, mode::*};
use crate::{RpcRead, RpcRouteKey, RpcStream, RpcWrite};

pub struct Router<K, S, St, Sp>
where
    K: RpcRouteKey,
    Sp: Spawner,
{
    config: RouterConfig,
    state: S,
    spawner: Sp,
    routes: Vec<RouteEntry<K, S, St, Sp>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Context {
    pub qid: QID,
    pub stream_id: StreamId,
}

struct RouteEntry<K, S, St, Sp>
where
    K: RpcRouteKey,
    Sp: Spawner,
{
    key: K,
    route: RouteFn<S, St, Sp>,
}

impl<K, S, St, Sp> RouteEntry<K, S, St, Sp>
where
    K: RpcRouteKey,
    Sp: Spawner,
{
    fn new(key: K, route: RouteFn<S, St, Sp>) -> Self {
        Self { key, route }
    }
}

impl<K, S, St, Sp> Router<K, S, St, Sp>
where
    K: RpcRouteKey,
    S: Clone + 'static,
    St: RpcStream,
    Sp: Spawner,
{
    pub fn builder_local(spawner: Sp) -> RouterBuilder<K, S, St, Sp, LocalRoutes>
    where
        Sp: LocalSpawner,
    {
        RouterBuilder::<K, S, St, Sp, LocalRoutes>::new(spawner)
    }

    pub fn builder_send(spawner: Sp) -> RouterBuilder<K, S, St, Sp, SendRoutes>
    where
        Sp: SendSpawner,
    {
        RouterBuilder::<K, S, St, Sp, SendRoutes>::new(spawner)
    }

    pub fn handle(&self, info: StreamInfo, stream: St) -> Option<Sp::Handle> {
        let StreamInfo {
            qid,
            stream_id,
            header,
        } = info;
        let context = Context { qid, stream_id };
        let Some(key) = K::decode(&header) else {
            let (mut reader, mut writer) = stream.split();
            reader.reset(ResetCode::PROTOCOL);
            writer.reset(ResetCode::PROTOCOL);
            return None;
        };
        let Ok(index) = self
            .routes
            .binary_search_by_key(&key, |entry| entry.key.clone())
        else {
            let (mut reader, mut writer) = stream.split();
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

    pub fn route_keys(&self) -> impl ExactSizeIterator<Item = &K> + '_ {
        self.routes.iter().map(|entry| &entry.key)
    }
}
