use dcbor::CBOR;

pub mod handshake;

use crate::wire::handshake::HandshakeMessage;

#[derive(Debug, Clone, PartialEq)]
pub enum QlMessage {
    Handshake(HandshakeMessage),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QlTag {
    Handshake = 0,
}

impl From<QlTag> for CBOR {
    fn from(value: QlTag) -> Self {
        CBOR::from(value as u8)
    }
}

impl TryFrom<CBOR> for QlTag {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let tag: u8 = value.try_into()?;
        match tag {
            0 => Ok(Self::Handshake),
            _ => Err(dcbor::Error::msg("unknown message tag")),
        }
    }
}

impl From<QlMessage> for CBOR {
    fn from(value: QlMessage) -> Self {
        match value {
            QlMessage::Handshake(message) => CBOR::from(vec![
                CBOR::from(QlTag::Handshake as u8),
                CBOR::from(message),
            ]),
        }
    }
}

impl TryFrom<CBOR> for QlMessage {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let array = value.try_into_array()?;
        if array.len() != 2 {
            return Err(dcbor::Error::msg("invalid array length"));
        }
        let mut iter = array.into_iter();
        let tag: QlTag = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("missing message tag"))?
            .try_into()?;
        let payload = iter
            .next()
            .ok_or_else(|| dcbor::Error::msg("missing message payload"))?;
        match tag {
            QlTag::Handshake => {
                let message = HandshakeMessage::try_from(payload)?;
                Ok(QlMessage::Handshake(message))
            }
        }
    }
}
