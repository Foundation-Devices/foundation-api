//! rpc protocol families built on top of one stream per call
//!
//! each trait in this module names one rpc shape and the typed values that
//! travel on that stream
//! route dispatch uses [`crate::RouteId`] and the submodules provide the matching
//! client and server helpers for encoding, decoding, and handler glue

pub mod download;
pub mod notification;
pub mod progress;
pub mod request;
pub mod subscription;
pub mod upload;
mod utils;

pub use download::Download;
pub use notification::Notification;
pub use progress::Progress;
pub use request::Request;
pub use subscription::Subscription;
pub use upload::Upload;
use utils::*;
