pub mod api;
pub use api::*;

/// Marker trait for types that have a Cbor derive (structs and enums, not primitives).
/// This is used to enforce that enum tuple variants wrap Cbor-derived types.
pub(crate) trait CborMarker {}
