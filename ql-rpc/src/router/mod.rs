use std::collections::HashMap;

use crate::{RouteId, StreamCloseCode};

mod builder;
mod config;
mod mode;

pub use self::{builder::RouterBuilder, config::RouterConfig, mode::*};
use crate::{close_stream, RpcStream};
pub use crate::{
    download::{DownloadHandler, DownloadResponder, DownloadWriter},
    notification::NotificationHandler,
    progress::{ProgressHandler, ProgressResponder},
    request::{RequestHandler, Response},
    subscription::{SubscriptionHandler, SubscriptionResponder},
};

pub struct Router<S, St, Sp>
where
    Sp: Spawner,
{
    config: RouterConfig,
    state: S,
    spawner: Sp,
    routes: HashMap<RouteId, RouteFn<S, St, Sp>>,
}

impl<S, St, Sp> Router<S, St, Sp>
where
    S: Clone + 'static,
    St: RpcStream,
    Sp: Spawner,
{
    pub fn builder(spawner: Sp) -> RouterBuilder<S, St, Sp> {
        RouterBuilder::<S, St, Sp>::new(spawner)
    }

    pub fn handle(&self, stream: St) -> Option<(RouteId, Sp::Handle)> {
        let route_id = stream.route_id()?;
        let Some(route) = self.routes.get(&route_id).copied() else {
            close_stream(stream, StreamCloseCode::UNKNOWN_ROUTE);
            return None;
        };
        Some((
            route_id,
            route(&self.spawner, self.state.clone(), self.config, stream),
        ))
    }
}
