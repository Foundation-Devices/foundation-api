//! rpc protocol families built on top of one stream per call
//!
//! each trait in this module names one rpc shape and the typed values that
//! travel on that stream
//! route dispatch uses [`crate::RouteId`] and the submodules provide the matching
//! client and server helpers for encoding, decoding, and handler glue

use crate::{RouteId, ServiceId};

pub mod download;
pub mod duplex;
pub mod notification;
pub(crate) mod parts;
pub mod progress;
pub mod request;
pub mod subscription;
pub mod upload;
mod utils;

pub trait Route {
    /// service used to scope this rpc route.
    const SERVICE: ServiceId;

    /// route used to dispatch this rpc family within [`Self::SERVICE`].
    const ROUTE: RouteId;
}

pub use download::Download;
pub use duplex::Duplex;
pub use notification::Notification;
pub use progress::Progress;
pub use request::Request;
pub use subscription::Subscription;
pub use upload::Upload;
use utils::*;
