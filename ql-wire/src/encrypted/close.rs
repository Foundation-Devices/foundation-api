use crate::{codec, codec::Reader, ByteSlice, WireEncode, WireError};

/// closes the whole session immediately with a close code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClose {
    pub code: SessionCloseCode,
}

impl SessionClose {
    pub const WIRE_SIZE: usize = size_of::<SessionCloseCode>();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SessionCloseCode(pub u16);

impl SessionCloseCode {
    pub const CANCELLED: Self = Self(0);
    pub const PROTOCOL: Self = Self(1);
    pub const TIMEOUT: Self = Self(2);
}

impl WireEncode for SessionCloseCode {
    fn encoded_len(&self) -> usize {
        size_of::<u16>()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for SessionCloseCode {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        Ok(Self(reader.decode()?))
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for SessionClose {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            code: reader.decode()?,
        })
    }
}

impl WireEncode for SessionClose {
    fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.code.encode(out);
    }
}
