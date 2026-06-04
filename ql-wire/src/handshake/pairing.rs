use std::fmt::{self, Display, Formatter};

use crate::{codec, ByteSlice, QlCrypto, WireEncode, WireError};

const PAIRING_ID_DOMAIN: &[u8] = b"ql-wire:pairing-id:v1";
const PAIRING_PSK_DOMAIN: &[u8] = b"ql-wire:pairing-psk:v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PairingToken(pub [u8; Self::SIZE]);

impl PairingToken {
    pub const SIZE: usize = 16;

    pub fn id(&self, crypto: &impl QlCrypto) -> PairingId {
        let hash = crypto.sha256(&[PAIRING_ID_DOMAIN, &self.0]);
        let mut id = [0u8; PairingId::SIZE];
        id.copy_from_slice(&hash[..PairingId::SIZE]);
        PairingId(id)
    }

    pub(super) fn psk(&self, crypto: &impl QlCrypto) -> [u8; 32] {
        crypto.sha256(&[PAIRING_PSK_DOMAIN, &self.0])
    }
}

impl Display for PairingToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl WireEncode for PairingToken {
    fn encoded_len(&self) -> usize {
        Self::SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for PairingToken {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self(reader.decode()?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PairingId(pub [u8; Self::SIZE]);

impl PairingId {
    pub const SIZE: usize = 16;
}

impl Display for PairingId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl WireEncode for PairingId {
    fn encoded_len(&self) -> usize {
        Self::SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for PairingId {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self(reader.decode()?))
    }
}
