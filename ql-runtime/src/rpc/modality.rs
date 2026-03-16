use std::fmt;

use dcbor::CBOR;

pub trait QlCodec: Into<CBOR> + TryFrom<CBOR, Error = dcbor::Error> {}

impl<T> QlCodec for T where T: Into<CBOR> + TryFrom<CBOR, Error = dcbor::Error> {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MethodId(pub u64);

impl fmt::Display for MethodId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<MethodId> for CBOR {
    fn from(value: MethodId) -> Self {
        CBOR::from(value.0)
    }
}

impl TryFrom<CBOR> for MethodId {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        Ok(Self(u64::try_from(value)?))
    }
}

pub trait RequestResponse: QlCodec {
    const METHOD: MethodId;
    type Response: QlCodec;
}
