use ql_common::QID;
use ql_wire::{ByteSlice, PairingToken, Reader, WireDecode, WireEncode, WireError};

/// Out-of-band invite consumed by the initiator of an XX pairing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingInvite {
    pub qid: QID,
    pub token: PairingToken,
}

impl PairingInvite {
    pub const VERSION: u8 = 1;
    pub const WIRE_SIZE: usize = size_of::<u8>() + QID::SIZE + PairingToken::SIZE;
}

impl WireEncode for PairingInvite {
    fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode<W: bytes::BufMut + ?Sized>(&self, out: &mut W) {
        Self::VERSION.encode(out);
        self.qid.encode(out);
        self.token.encode(out);
    }
}

impl<B: ByteSlice> WireDecode<B> for PairingInvite {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        if reader.decode::<u8>()? != Self::VERSION {
            return Err(WireError::InvalidPayload);
        }

        Ok(Self {
            qid: reader.decode()?,
            token: reader.decode()?,
        })
    }
}
