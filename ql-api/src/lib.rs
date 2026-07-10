#[macro_use]
mod macros;

pub mod app_store;
pub mod backup;
pub mod bitcoin;
pub mod codec;
pub mod debug;
pub mod firmware;
pub mod fx;
pub mod key;
pub mod onboarding;
pub mod scv;
pub mod system;
pub mod time;

pub use self::{
    app_store::*, backup::*, bitcoin::*, codec::Empty, debug::*, firmware::*, fx::*, key::*,
    onboarding::*, scv::*, system::*, time::*,
};

pub type Error = ciborium::de::Error<std::io::Error>;

// naming scheme
// Request:
// - Request{Thing}
// - {Thing}Params
// - {Thing}Response
// Subscription:
// - Subscribe{Thing}
// - {Thing}Params
// - {Thing}Event
// Download:
// - Download{Thing}
// - Download{Thing}Params
// - Download{Thing}Header
// - Download{Thing}PartHeader
// Upload:
// - Upload{Thing}
// - Upload{Thing}Params
// - Upload{Thing}PartHeader
// - Upload{Thing}Response
// Duplex:
// - {Action}{Thing}
// - {Action}{Thing}InitiatorEvent
// - {Action}{Thing}ResponderEvent
