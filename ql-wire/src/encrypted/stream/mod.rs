use rkyv::{Archive, Deserialize, Serialize};

use crate::StreamId;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StreamFrame {
    pub stream_id: StreamId,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub fin: bool,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StreamCloseFrame {
    pub stream_id: StreamId,
    pub target: CloseTarget,
    pub code: CloseCode,
    pub payload: Vec<u8>,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseTarget {
    Request = 1,
    Response = 2,
    Both = 3,
}

impl From<&ArchivedCloseTarget> for CloseTarget {
    fn from(value: &ArchivedCloseTarget) -> Self {
        match value {
            ArchivedCloseTarget::Request => Self::Request,
            ArchivedCloseTarget::Response => Self::Response,
            ArchivedCloseTarget::Both => Self::Both,
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CloseCode(pub u16);

impl CloseCode {
    pub const CANCELLED: Self = Self(0);
    pub const PROTOCOL: Self = Self(1);
    pub const INVALID_DATA: Self = Self(2);
    pub const TIMEOUT: Self = Self(3);

    pub const UNKNOWN: Self = Self(16);
    pub const UNKNOWN_ROUTE: Self = Self(17);
    pub const INVALID_HEAD: Self = Self(18);
    pub const BUSY: Self = Self(19);
    pub const UNHANDLED: Self = Self(20);
}

impl From<&ArchivedCloseCode> for CloseCode {
    fn from(value: &ArchivedCloseCode) -> Self {
        Self(value.0.to_native())
    }
}
