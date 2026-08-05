//! rpc protocol families built on top of one stream per call
//!
//! each trait in this module names one rpc shape and the typed values that
//! travel on that stream
//! route dispatch uses caller-defined route keys and the submodules provide the
//! matching client and server helpers for encoding, decoding, and handler glue

use bytes::BufMut;

pub mod download;
pub mod duplex;
pub mod notification;
pub(crate) mod parts;
pub mod progress;
pub mod request;
pub mod subscription;
pub mod upload;
mod utils;

pub trait RpcRouteKey: Sized + std::fmt::Debug + Ord + Clone + 'static {
    fn encoded_len(&self) -> usize;

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W);

    fn decode(bytes: &[u8]) -> Option<Self>;
}

pub trait Route {
    type Key: RpcRouteKey;

    fn key() -> Self::Key;
}

use utils::*;

pub use self::{
    download::Download,
    duplex::Duplex,
    notification::Notification,
    parts::{MultipartPart, MultipartReader},
    progress::Progress,
    request::Request,
    subscription::Subscription,
    upload::Upload,
};
