use crate::{ByteSlice, Reader, WireDecode, WireEncode, WireError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ServiceId(pub [u8; 16]);

impl ServiceId {
    pub const ENCODED_LEN: usize = size_of::<ServiceId>();
}

impl WireEncode for ServiceId {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}

impl<B: ByteSlice> WireDecode<B> for ServiceId {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        Ok(Self(reader.decode()?))
    }
}

impl std::fmt::Display for ServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
