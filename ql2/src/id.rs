use std::fmt;

use dcbor::CBOR;

macro_rules! define_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(pub u64);

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
