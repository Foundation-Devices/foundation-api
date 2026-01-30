use std::fmt;

use dcbor::CBOR;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(u64);

impl MessageId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for MessageId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<MessageId> for u64 {
    fn from(value: MessageId) -> Self {
        value.0
    }
}

impl From<MessageId> for CBOR {
    fn from(value: MessageId) -> Self {
        CBOR::from(value.0)
    }
}

impl TryFrom<CBOR> for MessageId {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let value: u64 = value.try_into()?;
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionEpoch(u64);

impl SessionEpoch {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    pub const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

impl fmt::Display for SessionEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for SessionEpoch {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<SessionEpoch> for u64 {
    fn from(value: SessionEpoch) -> Self {
        value.0
    }
}

impl From<SessionEpoch> for CBOR {
    fn from(value: SessionEpoch) -> Self {
        CBOR::from(value.0)
    }
}

impl TryFrom<CBOR> for SessionEpoch {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let value: u64 = value.try_into()?;
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteId(u64);

impl RouteId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for RouteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for RouteId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<RouteId> for u64 {
    fn from(value: RouteId) -> Self {
        value.0
    }
}

impl From<RouteId> for CBOR {
    fn from(value: RouteId) -> Self {
        CBOR::from(value.0)
    }
}

impl TryFrom<CBOR> for RouteId {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let value: u64 = value.try_into()?;
        Ok(Self(value))
    }
}
