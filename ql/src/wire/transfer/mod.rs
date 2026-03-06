use dcbor::CBOR;

use super::take_fields;
use crate::MessageId;

mod crypto;
pub use crypto::*;

#[derive(Debug, Clone, PartialEq)]
pub struct TransferBody {
    pub message_id: MessageId,
    pub valid_until: u64,
    pub transfer_id: MessageId,
    pub frame: TransferFrame,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransferFrame {
    Open { request_id: MessageId, meta: CBOR },
    Chunk { seq: u32, data: Vec<u8> },
    Finish { seq: u32 },
    Ack { next_seq: u32 },
    Cancel,
    CancelAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKind {
    Open = 1,
    Chunk,
    Finish,
    Ack,
    Cancel,
    CancelAck,
}

impl From<TransferBody> for CBOR {
    fn from(value: TransferBody) -> Self {
        CBOR::from(vec![
            CBOR::from(value.message_id),
            CBOR::from(value.valid_until),
            CBOR::from(value.transfer_id),
            CBOR::from(value.frame),
        ])
    }
}

impl TryFrom<CBOR> for TransferBody {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let iter = value.try_into_array()?.into_iter();
        let [message_id, valid_until, transfer_id, frame] = take_fields(iter)?;
        Ok(Self {
            message_id: message_id.try_into()?,
            valid_until: valid_until.try_into()?,
            transfer_id: transfer_id.try_into()?,
            frame: frame.try_into()?,
        })
    }
}

impl From<TransferFrame> for CBOR {
    fn from(value: TransferFrame) -> Self {
        match value {
            TransferFrame::Open { request_id, meta } => CBOR::from(vec![
                CBOR::from(TransferKind::Open as u8),
                CBOR::from(request_id),
                meta,
            ]),
            TransferFrame::Chunk { seq, data } => CBOR::from(vec![
                CBOR::from(TransferKind::Chunk as u8),
                CBOR::from(seq),
                CBOR::from(data),
            ]),
            TransferFrame::Finish { seq } => CBOR::from(vec![
                CBOR::from(TransferKind::Finish as u8),
                CBOR::from(seq),
            ]),
            TransferFrame::Ack { next_seq } => CBOR::from(vec![
                CBOR::from(TransferKind::Ack as u8),
                CBOR::from(next_seq),
            ]),
            TransferFrame::Cancel => CBOR::from(vec![CBOR::from(TransferKind::Cancel as u8)]),
            TransferFrame::CancelAck => CBOR::from(vec![CBOR::from(TransferKind::CancelAck as u8)]),
        }
    }
}

impl TryFrom<CBOR> for TransferFrame {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let mut iter = value.try_into_array()?.into_iter();
        let tag: TransferKind = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("missing transfer frame tag"))?
            .try_into()?;
        match tag {
            TransferKind::Open => {
                let [request_id, meta] = take_fields(iter)?;
                Ok(Self::Open {
                    request_id: request_id.try_into()?,
                    meta,
                })
            }
            TransferKind::Chunk => {
                let [seq, data] = take_fields(iter)?;
                Ok(Self::Chunk {
                    seq: seq.try_into()?,
                    data: data.try_into()?,
                })
            }
            TransferKind::Finish => {
                let [seq] = take_fields(iter)?;
                Ok(Self::Finish {
                    seq: seq.try_into()?,
                })
            }
            TransferKind::Ack => {
                let [next_seq] = take_fields(iter)?;
                Ok(Self::Ack {
                    next_seq: next_seq.try_into()?,
                })
            }
            TransferKind::Cancel => {
                if iter.next().is_some() {
                    Err(dcbor::Error::msg("array too long"))
                } else {
                    Ok(Self::Cancel)
                }
            }
            TransferKind::CancelAck => {
                if iter.next().is_some() {
                    Err(dcbor::Error::msg("array too long"))
                } else {
                    Ok(Self::CancelAck)
                }
            }
        }
    }
}

impl TryFrom<CBOR> for TransferKind {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let tag: u8 = value.try_into()?;
        match tag {
            1 => Ok(Self::Open),
            2 => Ok(Self::Chunk),
            3 => Ok(Self::Finish),
            4 => Ok(Self::Ack),
            5 => Ok(Self::Cancel),
            6 => Ok(Self::CancelAck),
            _ => Err(dcbor::Error::msg("unknown transfer frame tag")),
        }
    }
}
