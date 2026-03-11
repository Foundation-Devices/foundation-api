use rkyv::{Archive, Serialize};

use crate::{PacketId, QlError, StreamId};

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct StreamBody {
    pub packet_id: PacketId,
    pub valid_until: u64,
    pub packet_ack: Option<PacketAck>,
    pub frame: Option<StreamFrame>,
}

impl TryFrom<&ArchivedStreamBody> for StreamBody {
    type Error = QlError;

    fn try_from(value: &ArchivedStreamBody) -> Result<Self, Self::Error> {
        Ok(Self {
            packet_id: (&value.packet_id).into(),
            valid_until: value.valid_until.to_native(),
            packet_ack: value.packet_ack.as_ref().map(PacketAck::from),
            frame: value
                .frame
                .as_ref()
                .map(StreamFrame::try_from)
                .transpose()?,
        })
    }
}

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketAck {
    pub packet_id: PacketId,
}

impl From<&ArchivedPacketAck> for PacketAck {
    fn from(value: &ArchivedPacketAck) -> Self {
        Self {
            packet_id: (&value.packet_id).into(),
        }
    }
}

#[derive(Archive, Serialize, Debug, Clone, PartialEq, Eq)]
pub enum StreamFrame {
    Open(StreamFrameOpen),
    Accept(StreamFrameAccept),
    Reject(StreamFrameReject),
    Data(StreamFrameData),
    Credit(StreamFrameCredit),
    Finish(StreamFrameFinish),
    Reset(StreamFrameReset),
}

impl StreamFrame {
    pub fn stream_id(&self) -> StreamId {
        match self {
            StreamFrame::Open(StreamFrameOpen { stream_id, .. })
            | StreamFrame::Accept(StreamFrameAccept { stream_id, .. })
            | StreamFrame::Reject(StreamFrameReject { stream_id, .. })
            | StreamFrame::Data(StreamFrameData { stream_id, .. })
            | StreamFrame::Credit(StreamFrameCredit { stream_id, .. })
            | StreamFrame::Finish(StreamFrameFinish { stream_id, .. })
            | StreamFrame::Reset(StreamFrameReset { stream_id, .. }) => *stream_id,
        }
    }
}

impl TryFrom<&ArchivedStreamFrame> for StreamFrame {
    type Error = QlError;

    fn try_from(value: &ArchivedStreamFrame) -> Result<Self, Self::Error> {
        match value {
            ArchivedStreamFrame::Open(frame) => Ok(Self::Open(frame.into())),
            ArchivedStreamFrame::Accept(frame) => Ok(Self::Accept(frame.into())),
            ArchivedStreamFrame::Reject(frame) => Ok(Self::Reject(frame.into())),
            ArchivedStreamFrame::Data(frame) => Ok(Self::Data(frame.into())),
            ArchivedStreamFrame::Credit(frame) => Ok(Self::Credit(frame.into())),
            ArchivedStreamFrame::Finish(frame) => Ok(Self::Finish(frame.into())),
            ArchivedStreamFrame::Reset(frame) => Ok(Self::Reset(frame.into())),
        }
    }
}

#[derive(Archive, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct StreamFrameOpen {
    pub stream_id: StreamId,
    pub request_head: Vec<u8>,
    pub response_max_offset: u64,
}

impl From<&ArchivedStreamFrameOpen> for StreamFrameOpen {
    fn from(value: &ArchivedStreamFrameOpen) -> Self {
        Self {
            stream_id: (&value.stream_id).into(),
            request_head: value.request_head.as_slice().to_vec(),
            response_max_offset: value.response_max_offset.to_native(),
        }
    }
}

#[derive(Archive, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct StreamFrameAccept {
    pub stream_id: StreamId,
    pub response_head: Vec<u8>,
    pub request_max_offset: u64,
}

impl From<&ArchivedStreamFrameAccept> for StreamFrameAccept {
    fn from(value: &ArchivedStreamFrameAccept) -> Self {
        Self {
            stream_id: (&value.stream_id).into(),
            response_head: value.response_head.as_slice().to_vec(),
            request_max_offset: value.request_max_offset.to_native(),
        }
    }
}

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFrameCredit {
    pub stream_id: StreamId,
    pub dir: Direction,
    pub recv_offset: u64,
    pub max_offset: u64,
}

impl From<&ArchivedStreamFrameCredit> for StreamFrameCredit {
    fn from(value: &ArchivedStreamFrameCredit) -> Self {
        Self {
            stream_id: (&value.stream_id).into(),
            dir: (&value.dir).into(),
            recv_offset: value.recv_offset.to_native(),
            max_offset: value.max_offset.to_native(),
        }
    }
}

#[derive(Archive, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct StreamFrameData {
    pub stream_id: StreamId,
    pub dir: Direction,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

impl From<&ArchivedStreamFrameData> for StreamFrameData {
    fn from(value: &ArchivedStreamFrameData) -> Self {
        Self {
            stream_id: (&value.stream_id).into(),
            dir: (&value.dir).into(),
            offset: value.offset.to_native(),
            bytes: value.bytes.as_slice().to_vec(),
        }
    }
}

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFrameFinish {
    pub stream_id: StreamId,
    pub dir: Direction,
}

impl From<&ArchivedStreamFrameFinish> for StreamFrameFinish {
    fn from(value: &ArchivedStreamFrameFinish) -> Self {
        Self {
            stream_id: (&value.stream_id).into(),
            dir: (&value.dir).into(),
        }
    }
}

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFrameReset {
    pub stream_id: StreamId,
    pub dir: ResetTarget,
    pub code: ResetCode,
}

impl From<&ArchivedStreamFrameReset> for StreamFrameReset {
    fn from(value: &ArchivedStreamFrameReset) -> Self {
        Self {
            stream_id: (&value.stream_id).into(),
            dir: (&value.dir).into(),
            code: (&value.code).into(),
        }
    }
}

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Archive, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
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
