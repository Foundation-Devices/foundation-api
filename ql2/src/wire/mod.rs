use dcbor::CBOR;

pub mod handshake;
pub mod pairing;

use crate::wire::handshake::HandshakeMessage;
use crate::wire::pairing::PairingRequest;

#[derive(Debug, Clone, PartialEq)]
pub enum QlMessage {
    Handshake(HandshakeMessage),
    Pairing(PairingRequest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QlTag {
    Handshake = 1,
    Pairing = 2,
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
            1 => Ok(Self::Handshake),
            2 => Ok(Self::Pairing),
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
            QlMessage::Pairing(message) => CBOR::from(vec![
                CBOR::from(QlTag::Pairing as u8),
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
            QlTag::Pairing => {
                let message = PairingRequest::try_from(payload)?;
                Ok(QlMessage::Pairing(message))
            }
        }
    }
}

pub(crate) fn take_fields<const N: usize>(
    mut iter: impl Iterator<Item = CBOR>,
) -> Result<[CBOR; N], dcbor::Error> {
    use std::mem::MaybeUninit;

    let mut fields: [MaybeUninit<CBOR>; N] = unsafe { MaybeUninit::uninit().assume_init() };
    for (index, slot) in fields.iter_mut().enumerate() {
        let Some(value) = iter.next() else {
            for init in &mut fields[..index] {
                unsafe { init.assume_init_drop() };
            }
            return Err(dcbor::Error::msg("array too short"));
        };
        slot.write(value);
    }
    let result = unsafe { std::ptr::read(&fields as *const _ as *const [CBOR; N]) };
    if iter.next().is_some() {
        return Err(dcbor::Error::msg("array too long"));
    }
    Ok(result)
}

#[test]
fn take_fields_reads_exact_count() {
    let values = vec![CBOR::from(1u8), CBOR::from(2u8), CBOR::from(3u8)];
    let mut iter = values.into_iter();
    let [first, second, third] = take_fields(&mut iter).unwrap();
    assert_eq!(u8::try_from(first).unwrap(), 1);
    assert_eq!(u8::try_from(second).unwrap(), 2);
    assert_eq!(u8::try_from(third).unwrap(), 3);
    assert!(iter.next().is_none());
}

#[test]
fn take_fields_rejects_short_arrays() {
    let values = vec![CBOR::from(1u8)];
    let mut iter = values.into_iter();
    let result: Result<[CBOR; 2], _> = take_fields(&mut iter);
    assert!(result.is_err());
}
