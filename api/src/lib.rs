pub mod api;
pub use api::*;
pub mod v2;

/// Marker trait for types that have a Cbor derive (structs and enums, not primitives).
/// This is used to enforce that enum tuple variants wrap Cbor-derived types.
pub(crate) trait CborMarker {}

pub use bc_components;
pub use bc_envelope;
pub use bc_xid;
pub use dcbor;
