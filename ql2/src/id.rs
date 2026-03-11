use std::fmt;

use dcbor::CBOR;
use rkyv::{Archive, Serialize};

macro_rules! define_id {
    ($name:ident) => {
        #[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u64);

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
                Ok(Self(u64::try_from(value)?))
            }
        }
    };
}

define_id!(MessageId);
define_id!(PacketId);
define_id!(StreamId);

impl From<&ArchivedMessageId> for MessageId {
    fn from(value: &ArchivedMessageId) -> Self {
        Self(value.0.to_native())
    }
}

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

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(pub u64);

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
