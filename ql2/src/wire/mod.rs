use dcbor::CBOR;

pub mod handshake;
pub mod message;
pub mod pair;

use bc_components::{EncryptedMessage, XID};

use crate::wire::{handshake::HandshakeRecord, pair::PairRequestRecord};

#[derive(Debug, Clone, PartialEq)]
pub struct QlRecord {
    pub header: QlHeader,
    pub payload: QlPayload,
}

#[derive(Debug, Clone, PartialEq)]
pub struct QlHeader {
    pub sender: XID,
    pub recipient: XID,
}

impl QlHeader {
    pub fn aad(&self) -> Vec<u8> {
        CBOR::from(self.clone()).to_cbor_data()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum QlPayload {
    Handshake(HandshakeRecord),
    Pair(PairRequestRecord),
    Message(EncryptedMessage),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QlTag {
    Handshake = 1,
    Pairing = 2,
    Record = 3,
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
            3 => Ok(Self::Record),
            _ => Err(dcbor::Error::msg("unknown message tag")),
        }
    }
}

impl From<QlRecord> for CBOR {
    fn from(value: QlRecord) -> Self {
        let (tag, payload) = match value.payload {
            QlPayload::Handshake(message) => (QlTag::Handshake, CBOR::from(message)),
            QlPayload::Pair(message) => (QlTag::Pairing, CBOR::from(message)),
            QlPayload::Message(message) => (QlTag::Record, CBOR::from(message)),
        };
        CBOR::from(vec![
            CBOR::from(tag as u8),
            CBOR::from(value.header),
            payload,
        ])
    }
}

impl TryFrom<CBOR> for QlRecord {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let iter = value.try_into_array()?.into_iter();
        let [tag_cbor, header_cbor, payload] = take_fields(iter)?;
        let tag = QlTag::try_from(tag_cbor)?;
        let header = QlHeader::try_from(header_cbor)?;
        match tag {
            QlTag::Handshake => {
                let message = HandshakeRecord::try_from(payload)?;
                Ok(QlRecord {
                    header,
                    payload: QlPayload::Handshake(message),
                })
            }
            QlTag::Pairing => {
                let message = PairRequestRecord::try_from(payload)?;
                Ok(QlRecord {
                    header,
                    payload: QlPayload::Pair(message),
                })
            }
            QlTag::Record => {
                let message = EncryptedMessage::try_from(payload)?;
                Ok(QlRecord {
                    header,
                    payload: QlPayload::Message(message),
                })
            }
        }
    }
}

impl From<QlHeader> for CBOR {
    fn from(value: QlHeader) -> Self {
        CBOR::from(vec![CBOR::from(value.sender), CBOR::from(value.recipient)])
    }
}

impl TryFrom<CBOR> for QlHeader {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let iter = value.try_into_array()?.into_iter();
        let [sender_cbor, recipient_cbor] = take_fields(iter)?;
        Ok(Self {
            sender: sender_cbor.try_into()?,
            recipient: recipient_cbor.try_into()?,
        })
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
