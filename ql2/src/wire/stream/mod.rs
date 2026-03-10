use dcbor::CBOR;

use super::take_fields;
use crate::{PacketId, RouteId, StreamId};

mod crypto;
pub use crypto::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamBody {
    pub packet_id: PacketId,
    pub valid_until: u64,
    pub packet_ack: Option<PacketAck>,
    pub frame: Option<StreamFrame>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketAck {
    pub packet_id: PacketId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFrameOpen {
    pub stream_id: StreamId,
    pub route_id: RouteId,
    pub request_head: Vec<u8>,
    pub response_max_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFrameAccept {
    pub stream_id: StreamId,
    pub response_head: Vec<u8>,
    pub request_max_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFrameReject {
    pub stream_id: StreamId,
    pub code: RejectCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFrameCredit {
    pub stream_id: StreamId,
    pub dir: Direction,
    pub recv_offset: u64,
    pub max_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFrameData {
    pub stream_id: StreamId,
    pub dir: Direction,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFrameFinish {
    pub stream_id: StreamId,
    pub dir: Direction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFrameReset {
    pub stream_id: StreamId,
    pub dir: ResetTarget,
    pub code: ResetCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Request = 1,
    Response = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetTarget {
    Request = 1,
    Response = 2,
    Both = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectCode {
    Unknown = 0,
    UnknownRoute = 1,
    InvalidHead = 2,
    Busy = 3,
    Unhandled = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetCode {
    Cancelled = 0,
    InvalidData = 1,
    Protocol = 2,
    Timeout = 3,
}

impl From<StreamBody> for CBOR {
    fn from(value: StreamBody) -> Self {
        CBOR::from(vec![
            CBOR::from(value.packet_id),
            CBOR::from(value.valid_until),
            value.packet_ack.map(CBOR::from).unwrap_or_else(CBOR::null),
            value.frame.map(CBOR::from).unwrap_or_else(CBOR::null),
        ])
    }
}

impl TryFrom<CBOR> for StreamBody {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let iter = value.try_into_array()?.into_iter();
        let [packet_id, valid_until, packet_ack, frame] = take_fields(iter)?;
        Ok(Self {
            packet_id: packet_id.try_into()?,
            valid_until: valid_until.try_into()?,
            packet_ack: if packet_ack.is_null() {
                None
            } else {
                Some(packet_ack.try_into()?)
            },
            frame: if frame.is_null() {
                None
            } else {
                Some(frame.try_into()?)
            },
        })
    }
}

impl From<PacketAck> for CBOR {
    fn from(value: PacketAck) -> Self {
        CBOR::from(value.packet_id)
    }
}

impl TryFrom<CBOR> for PacketAck {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        Ok(Self {
            packet_id: value.try_into()?,
        })
    }
}

impl From<StreamFrame> for CBOR {
    fn from(value: StreamFrame) -> Self {
        match value {
            StreamFrame::Open(StreamFrameOpen {
                stream_id,
                route_id,
                request_head,
                response_max_offset,
            }) => CBOR::from(vec![
                CBOR::from(1u8),
                CBOR::from(stream_id),
                CBOR::from(route_id),
                CBOR::from(request_head),
                CBOR::from(response_max_offset),
            ]),
            StreamFrame::Accept(StreamFrameAccept {
                stream_id,
                response_head,
                request_max_offset,
            }) => CBOR::from(vec![
                CBOR::from(2u8),
                CBOR::from(stream_id),
                CBOR::from(response_head),
                CBOR::from(request_max_offset),
            ]),
            StreamFrame::Reject(StreamFrameReject { stream_id, code }) => CBOR::from(vec![
                CBOR::from(3u8),
                CBOR::from(stream_id),
                CBOR::from(code),
            ]),
            StreamFrame::Data(StreamFrameData {
                stream_id,
                dir,
                offset,
                bytes,
            }) => CBOR::from(vec![
                CBOR::from(4u8),
                CBOR::from(stream_id),
                CBOR::from(dir),
                CBOR::from(offset),
                CBOR::from(bytes),
            ]),
            StreamFrame::Credit(StreamFrameCredit {
                stream_id,
                dir,
                recv_offset,
                max_offset,
            }) => CBOR::from(vec![
                CBOR::from(5u8),
                CBOR::from(stream_id),
                CBOR::from(dir),
                CBOR::from(recv_offset),
                CBOR::from(max_offset),
            ]),
            StreamFrame::Finish(StreamFrameFinish { stream_id, dir }) => CBOR::from(vec![
                CBOR::from(6u8),
                CBOR::from(stream_id),
                CBOR::from(dir),
            ]),
            StreamFrame::Reset(StreamFrameReset {
                stream_id,
                dir,
                code,
            }) => CBOR::from(vec![
                CBOR::from(7u8),
                CBOR::from(stream_id),
                CBOR::from(dir),
                CBOR::from(code),
            ]),
        }
    }
}

impl TryFrom<CBOR> for StreamFrame {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let mut iter = value.try_into_array()?.into_iter();
        let tag: u8 = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("missing stream frame tag"))?
            .try_into()?;
        match tag {
            1 => {
                let [stream_id, route_id, request_head, response_max_offset] = take_fields(iter)?;
                Ok(Self::Open(StreamFrameOpen {
                    stream_id: stream_id.try_into()?,
                    route_id: route_id.try_into()?,
                    request_head: request_head.try_into()?,
                    response_max_offset: response_max_offset.try_into()?,
                }))
            }
            2 => {
                let [stream_id, response_head, request_max_offset] = take_fields(iter)?;
                Ok(Self::Accept(StreamFrameAccept {
                    stream_id: stream_id.try_into()?,
                    response_head: response_head.try_into()?,
                    request_max_offset: request_max_offset.try_into()?,
                }))
            }
            3 => {
                let [stream_id, code] = take_fields(iter)?;
                Ok(Self::Reject(StreamFrameReject {
                    stream_id: stream_id.try_into()?,
                    code: code.try_into()?,
                }))
            }
            4 => {
                let [stream_id, dir, offset, bytes] = take_fields(iter)?;
                Ok(Self::Data(StreamFrameData {
                    stream_id: stream_id.try_into()?,
                    dir: dir.try_into()?,
                    offset: offset.try_into()?,
                    bytes: bytes.try_into()?,
                }))
            }
            5 => {
                let [stream_id, dir, recv_offset, max_offset] = take_fields(iter)?;
                Ok(Self::Credit(StreamFrameCredit {
                    stream_id: stream_id.try_into()?,
                    dir: dir.try_into()?,
                    recv_offset: recv_offset.try_into()?,
                    max_offset: max_offset.try_into()?,
                }))
            }
            6 => {
                let [stream_id, dir] = take_fields(iter)?;
                Ok(Self::Finish(StreamFrameFinish {
                    stream_id: stream_id.try_into()?,
                    dir: dir.try_into()?,
                }))
            }
            7 => {
                let [stream_id, dir, code] = take_fields(iter)?;
                Ok(Self::Reset(StreamFrameReset {
                    stream_id: stream_id.try_into()?,
                    dir: dir.try_into()?,
                    code: code.try_into()?,
                }))
            }
            _ => Err(dcbor::Error::msg("unknown stream frame tag")),
        }
    }
}

impl From<Direction> for CBOR {
    fn from(value: Direction) -> Self {
        CBOR::from(value as u8)
    }
}

impl TryFrom<CBOR> for Direction {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        match u8::try_from(value)? {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            _ => Err(dcbor::Error::msg("unknown direction")),
        }
    }
}

impl From<ResetTarget> for CBOR {
    fn from(value: ResetTarget) -> Self {
        CBOR::from(value as u8)
    }
}

impl TryFrom<CBOR> for ResetTarget {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        match u8::try_from(value)? {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Both),
            _ => Err(dcbor::Error::msg("unknown reset target")),
        }
    }
}

impl From<RejectCode> for CBOR {
    fn from(value: RejectCode) -> Self {
        CBOR::from(value as u8)
    }
}

impl TryFrom<CBOR> for RejectCode {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        Ok(match u8::try_from(value)? {
            0 => Self::Unknown,
            1 => Self::UnknownRoute,
            2 => Self::InvalidHead,
            3 => Self::Busy,
            4 => Self::Unhandled,
            _ => return Err(dcbor::Error::msg("unknown reject code")),
        })
    }
}

impl From<ResetCode> for CBOR {
    fn from(value: ResetCode) -> Self {
        CBOR::from(value as u8)
    }
}

impl TryFrom<CBOR> for ResetCode {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        Ok(match u8::try_from(value)? {
            0 => Self::Cancelled,
            1 => Self::InvalidData,
            2 => Self::Protocol,
            3 => Self::Timeout,
            _ => return Err(dcbor::Error::msg("unknown reset code")),
        })
    }
}
