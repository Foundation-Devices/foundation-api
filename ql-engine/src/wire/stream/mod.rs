use rkyv::{Archive, Deserialize, Serialize};

use crate::{wire::StreamSeq, StreamId};

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum StreamBody {
    Ack(StreamAckBody),
    Message(StreamMessage),
}

impl StreamBody {
    pub fn stream_id(&self) -> StreamId {
        match self {
            Self::Ack(StreamAckBody { stream_id, .. }) => *stream_id,
            Self::Message(message) => message.frame.stream_id(),
        }
    }

    pub fn valid_until(&self) -> u64 {
        match self {
            Self::Ack(body) => body.valid_until,
            Self::Message(message) => message.valid_until,
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamAckBody {
    pub stream_id: StreamId,
    pub ack: StreamAck,
    pub valid_until: u64,
}

impl From<&ArchivedStreamAckBody> for StreamAckBody {
    fn from(value: &ArchivedStreamAckBody) -> Self {
        Self {
            stream_id: (&value.stream_id).into(),
            ack: (&value.ack).into(),
            valid_until: value.valid_until.to_native(),
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StreamMessage {
    pub tx_seq: StreamSeq,
    pub ack: StreamAck,
    pub valid_until: u64,
    pub frame: StreamFrame,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamAck {
    pub base: StreamSeq,
    pub bitmap: u8,
}

impl From<&ArchivedStreamAck> for StreamAck {
    fn from(value: &ArchivedStreamAck) -> Self {
        Self {
            base: (&value.base).into(),
            bitmap: value.bitmap,
        }
    }
}

impl StreamAck {
    pub const EMPTY: Self = Self {
        base: StreamSeq(0),
        bitmap: 0,
    };
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum StreamFrame {
    Open(StreamFrameOpen),
    Data(StreamFrameData),
    Close(StreamFrameClose),
}

impl StreamFrame {
    pub fn stream_id(&self) -> StreamId {
        match self {
            StreamFrame::Open(StreamFrameOpen { stream_id, .. })
            | StreamFrame::Data(StreamFrameData { stream_id, .. })
            | StreamFrame::Close(StreamFrameClose { stream_id, .. }) => *stream_id,
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BodyChunk {
    pub bytes: Vec<u8>,
    pub fin: bool,
}

impl From<&ArchivedBodyChunk> for BodyChunk {
    fn from(value: &ArchivedBodyChunk) -> Self {
        Self {
            bytes: value.bytes.as_slice().to_vec(),
            fin: value.fin,
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StreamFrameOpen {
    pub stream_id: StreamId,
    pub request_head: Vec<u8>,
    pub request_prefix: Option<BodyChunk>,
}

impl From<&ArchivedStreamFrameOpen> for StreamFrameOpen {
    fn from(value: &ArchivedStreamFrameOpen) -> Self {
        Self {
            stream_id: (&value.stream_id).into(),
            request_head: value.request_head.as_slice().to_vec(),
            request_prefix: value.request_prefix.as_ref().map(Into::into),
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StreamFrameData {
    pub stream_id: StreamId,
    pub chunk: BodyChunk,
}

impl From<&ArchivedStreamFrameData> for StreamFrameData {
    fn from(value: &ArchivedStreamFrameData) -> Self {
        Self {
            stream_id: (&value.stream_id).into(),
            chunk: (&value.chunk).into(),
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StreamFrameClose {
    pub stream_id: StreamId,
    pub target: CloseTarget,
    pub code: CloseCode,
    pub payload: Vec<u8>,
}

impl From<&ArchivedStreamFrameClose> for StreamFrameClose {
    fn from(value: &ArchivedStreamFrameClose) -> Self {
        Self {
            stream_id: (&value.stream_id).into(),
            target: (&value.target).into(),
            code: (&value.code).into(),
            payload: value.payload.as_slice().to_vec(),
        }
    }
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
