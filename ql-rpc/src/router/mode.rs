use std::{future::Future, pin::Pin};

use crate::RouterConfig;

pub type RouteFn<S, St, Sp> = fn(&Sp, S, RouterConfig, St) -> <Sp as Spawner>::Handle;

pub trait Spawner {
    type Handle: Future<Output = ()> + 'static;
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

#[derive(Debug, Clone, Copy, Default)]
pub struct LocalSpawn;

impl Spawner for LocalSpawn {
    type Handle = Pin<Box<dyn Future<Output = ()> + 'static>>;
}

impl LocalSpawner for LocalSpawn {
    fn spawn<F>(&self, fut: F) -> Self::Handle
    where
        F: Future<Output = ()> + 'static,
    {
        Box::pin(fut)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SendSpawn;

impl Spawner for SendSpawn {
    type Handle = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
}

impl SendSpawner for SendSpawn {
    fn spawn<F>(&self, fut: F) -> Self::Handle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Box::pin(fut)
    }
}
