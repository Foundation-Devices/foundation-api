use ql_codec::{ByteSlice, Decode, Encode, Reader};
use ql_common::QID;
use ql_wire::PairingToken;

/// Out-of-band invite consumed by the initiator of an XX pairing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingInvite {
    pub qid: QID,
    pub token: PairingToken,
}

impl PairingInvite {
    pub const VERSION: u8 = 1;
}

impl Encode for PairingInvite {
    fn encoded_len(&self) -> usize {
        size_of::<u8>() + QID::SIZE + PairingToken::SIZE
    }

    fn encode<W: bytes::BufMut + ?Sized>(&self, out: &mut W) {
        Self::VERSION.encode(out);
        self.qid.encode(out);
        self.token.encode(out);
    }
}

impl<B: ByteSlice> Decode<B> for PairingInvite {
    fn decode(reader: &mut Reader<B>) -> Result<Self, ql_codec::Error> {
        if reader.decode::<u8>()? != Self::VERSION {
            return Err(ql_codec::Error::InvalidDiscriminant);
        }

        Ok(Self {
            qid: reader.decode()?,
            token: reader.decode()?,
        })
    }
}
