use rkyv::{Archive, Serialize};

use crate::{MessageId, QlError};

mod crypto;
pub use crypto::*;

#[derive(Archive, Serialize, Debug, Clone, PartialEq)]
pub struct HeartbeatBody {
    pub message_id: MessageId,
    pub valid_until: u64,
}

impl TryFrom<&ArchivedHeartbeatBody> for HeartbeatBody {
    type Error = QlError;

    fn try_from(value: &ArchivedHeartbeatBody) -> Result<Self, Self::Error> {
        Ok(Self {
            message_id: (&value.message_id).into(),
            valid_until: value.valid_until.to_native(),
        })
    }
}
