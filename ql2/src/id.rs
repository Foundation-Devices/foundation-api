use std::fmt;

use dcbor::CBOR;
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
        pub struct $name(pub $ty);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<$name> for CBOR {
            fn from(value: $name) -> Self {
                CBOR::from(value.0)
            }
        }

        impl TryFrom<CBOR> for $name {
            type Error = dcbor::Error;

            fn try_from(value: CBOR) -> Result<Self, Self::Error> {
                Ok(Self(<$ty>::try_from(value)?))
            }
        }
    };
}

define_id!(PacketId, u32);
define_id!(StreamId, u64);

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
