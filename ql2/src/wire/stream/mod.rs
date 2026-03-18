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
    pub ack: Option<StreamAck>,
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

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum StreamFrame {
    Open(StreamFrameOpen),
    Accept(StreamFrameAccept),
    Reject(StreamFrameReject),
    Data(StreamFrameData),
    Reset(StreamFrameReset),
}

impl StreamFrame {
    pub fn stream_id(&self) -> StreamId {
        match self {
            StreamFrame::Open(StreamFrameOpen { stream_id, .. })
            | StreamFrame::Accept(StreamFrameAccept { stream_id, .. })
            | StreamFrame::Reject(StreamFrameReject { stream_id, .. })
            | StreamFrame::Data(StreamFrameData { stream_id, .. })
            | StreamFrame::Reset(StreamFrameReset { stream_id, .. }) => *stream_id,
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
pub struct StreamFrameAccept {
    pub stream_id: StreamId,
    pub response_head: Vec<u8>,
    pub response_prefix: Option<BodyChunk>,
}

impl From<&ArchivedStreamFrameAccept> for StreamFrameAccept {
    fn from(value: &ArchivedStreamFrameAccept) -> Self {
        Self {
            stream_id: (&value.stream_id).into(),
            response_head: value.response_head.as_slice().to_vec(),
            response_prefix: value.response_prefix.as_ref().map(Into::into),
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFrameReject {
    pub stream_id: StreamId,
    pub code: RejectCode,
}

impl From<&ArchivedStreamFrameReject> for StreamFrameReject {
    fn from(value: &ArchivedStreamFrameReject) -> Self {
        Self {
            stream_id: (&value.stream_id).into(),
            code: (&value.code).into(),
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StreamFrameData {
    pub stream_id: StreamId,
    pub dir: Direction,
    pub chunk: BodyChunk,
}

impl From<&ArchivedStreamFrameData> for StreamFrameData {
    fn from(value: &ArchivedStreamFrameData) -> Self {
        Self {
            stream_id: (&value.stream_id).into(),
            dir: (&value.dir).into(),
            chunk: (&value.chunk).into(),
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFrameReset {
    pub stream_id: StreamId,
    pub target: ResetTarget,
    pub code: ResetCode,
}

impl From<&ArchivedStreamFrameReset> for StreamFrameReset {
    fn from(value: &ArchivedStreamFrameReset) -> Self {
        Self {
            stream_id: (&value.stream_id).into(),
            target: (&value.target).into(),
            code: (&value.code).into(),
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    Request = 1,
    Response = 2,
}

impl From<&ArchivedDirection> for Direction {
    fn from(value: &ArchivedDirection) -> Self {
        match value {
            ArchivedDirection::Request => Self::Request,
            ArchivedDirection::Response => Self::Response,
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResetTarget {
    Request = 1,
    Response = 2,
    Both = 3,
}

impl From<&ArchivedResetTarget> for ResetTarget {
    fn from(value: &ArchivedResetTarget) -> Self {
        match value {
            ArchivedResetTarget::Request => Self::Request,
            ArchivedResetTarget::Response => Self::Response,
            ArchivedResetTarget::Both => Self::Both,
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RejectCode {
    Unknown = 0,
    UnknownRoute = 1,
    InvalidHead = 2,
    Busy = 3,
    Unhandled = 4,
}

impl From<&ArchivedRejectCode> for RejectCode {
    fn from(value: &ArchivedRejectCode) -> Self {
        match value {
            ArchivedRejectCode::Unknown => Self::Unknown,
            ArchivedRejectCode::UnknownRoute => Self::UnknownRoute,
            ArchivedRejectCode::InvalidHead => Self::InvalidHead,
            ArchivedRejectCode::Busy => Self::Busy,
            ArchivedRejectCode::Unhandled => Self::Unhandled,
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResetCode {
    Cancelled = 0,
    InvalidData = 1,
    Protocol = 2,
    Timeout = 3,
}

impl From<&ArchivedResetCode> for ResetCode {
    fn from(value: &ArchivedResetCode) -> Self {
        match value {
            ArchivedResetCode::Cancelled => Self::Cancelled,
            ArchivedResetCode::InvalidData => Self::InvalidData,
            ArchivedResetCode::Protocol => Self::Protocol,
            ArchivedResetCode::Timeout => Self::Timeout,
        }
    }
}
