use crate::{wire::message::Nack, MessageId, QlError};

pub mod handshake;
pub mod heartbeat;
pub mod message;
pub mod pair;

fn ensure_not_expired(id: MessageId, valid_until: u64) -> Result<(), QlError> {
    let now = now_secs();
    if now > valid_until {
        Err(QlError::Nack {
            id,
            nack: Nack::Expired,
        })
    } else {
        Ok(())
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
