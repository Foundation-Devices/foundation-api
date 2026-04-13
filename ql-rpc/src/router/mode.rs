use std::{future::Future, pin::Pin};

use crate::RouterConfig;

pub trait RouteMode {
    type RouteFuture: Future<Output = ()> + 'static;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LocalMode;

#[derive(Debug, Clone, Copy, Default)]
pub struct SendMode;

pub type RouteFn<S, St, Mode> = fn(S, RouterConfig, St) -> <Mode as RouteMode>::RouteFuture;
pub type LocalFuture = Pin<Box<dyn Future<Output = ()> + 'static>>;
pub type SendFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

impl RouteMode for LocalMode {
    type RouteFuture = LocalFuture;
}

impl RouteMode for SendMode {
    type RouteFuture = SendFuture;
}
