use std::fmt;

use rkyv::{Archive, Deserialize, Serialize};

macro_rules! define_id {
    ($name:ident, $ty:ty) => {
        #[derive(
            Archive,
            Serialize,
            Deserialize,
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
        )]
        #[repr(transparent)]
        pub struct $name(pub $ty);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

define_id!(PacketId, u32);
define_id!(StreamId, u32);

impl From<&ArchivedPacketId> for PacketId {
    fn from(value: &ArchivedPacketId) -> Self {
        Self(value.0.to_native())
    }
}

impl From<&ArchivedStreamId> for StreamId {
    fn from(value: &ArchivedStreamId) -> Self {
        Self(value.0.to_native())
    }
}
