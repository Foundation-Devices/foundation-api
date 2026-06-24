use std::future::Future;

use super::Context;
use crate::RouterConfig;

pub type RouteFn<S, St, Sp> = fn(&Sp, S, Context, RouterConfig, St) -> <Sp as Spawner>::Handle;

pub trait Spawner: Clone + 'static {
    type Handle;
}

pub trait LocalSpawner: Spawner {
    fn spawn<F>(&self, fut: F) -> Self::Handle
    where
        F: Future<Output = ()> + 'static;
}

pub trait SendSpawner: Spawner {
    fn spawn<F>(&self, fut: F) -> Self::Handle
    where
        F: Future<Output = ()> + Send + 'static;
}
