use bc_components::XID;
use dcbor::CBOR;

use super::take_fields;
use crate::{MessageId, RouteId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    Request,
    Response,
    Event,
    Nack,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecordBody {
    pub message_id: MessageId,
    pub valid_until: u64,
    pub kind: RecordKind,
    pub route_id: RouteId,
    pub payload: CBOR,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecryptedRecord {
    pub sender: XID,
    pub recipient: XID,
    pub kind: RecordKind,
    pub message_id: MessageId,
    pub route_id: RouteId,
    pub valid_until: u64,
    pub payload: CBOR,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nack {
    Unknown,
    UnknownRoute,
    InvalidPayload,
    Expired,
}

impl From<RecordKind> for CBOR {
    fn from(value: RecordKind) -> Self {
        let kind = match value {
            RecordKind::Request => 1,
            RecordKind::Response => 2,
            RecordKind::Event => 3,
            RecordKind::Nack => 6,
        };
        CBOR::from(kind)
    }
}

impl TryFrom<CBOR> for RecordKind {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let kind: u64 = value.try_into()?;
        match kind {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Event),
            6 => Ok(Self::Nack),
            _ => Err(dcbor::Error::msg("unknown record kind")),
        }
    }
}

impl From<RecordBody> for CBOR {
    fn from(value: RecordBody) -> Self {
        CBOR::from(vec![
            CBOR::from(value.message_id),
            CBOR::from(value.valid_until),
            CBOR::from(value.kind),
            CBOR::from(value.route_id),
            value.payload,
        ])
    }
}

impl TryFrom<CBOR> for RecordBody {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let iter = value.try_into_array()?.into_iter();
        let [message_id, valid_until, kind, route_id, payload] = take_fields(iter)?;
        Ok(Self {
            message_id: message_id.try_into()?,
            valid_until: valid_until.try_into()?,
            kind: kind.try_into()?,
            route_id: route_id.try_into()?,
            payload,
        })
    }
}

impl From<Nack> for CBOR {
    fn from(value: Nack) -> Self {
        let value = match value {
            Nack::Unknown => 0,
            Nack::UnknownRoute => 1,
            Nack::InvalidPayload => 2,
            Nack::Expired => 3,
        };
        CBOR::from(value)
    }
}

impl From<CBOR> for Nack {
    fn from(value: CBOR) -> Self {
        let value: u8 = value.try_into().unwrap_or_default();
        match value {
            1 => Nack::UnknownRoute,
            2 => Nack::InvalidPayload,
            3 => Nack::Expired,
            _ => Nack::Unknown,
        }
    }
}
