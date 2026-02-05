use dcbor::CBOR;

use super::take_fields;
use crate::MessageId;

#[derive(Debug, Clone, PartialEq)]
pub struct HeartbeatBody {
    pub message_id: MessageId,
    pub valid_until: u64,
}

impl From<HeartbeatBody> for CBOR {
    fn from(value: HeartbeatBody) -> Self {
        CBOR::from(vec![
            CBOR::from(value.message_id),
            CBOR::from(value.valid_until),
        ])
    }
}

impl TryFrom<CBOR> for HeartbeatBody {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let iter = value.try_into_array()?.into_iter();
        let [message_id, valid_until] = take_fields(iter)?;
        Ok(Self {
            message_id: message_id.try_into()?,
            valid_until: valid_until.try_into()?,
        })
    }
}
