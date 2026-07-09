use ql_codec::{ByteSlice, Encode};

/// closes the whole session immediately with a reset code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClose {
    pub code: SessionCloseCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SessionCloseCode(pub u64);

impl SessionCloseCode {
    pub const CANCELLED: Self = Self(0);
    pub const PROTOCOL: Self = Self(1);
    pub const TIMEOUT: Self = Self(2);
}

ql_codec::varint_wrapper!(SessionCloseCode, u64);

impl<B: ByteSlice> ql_codec::Decode<B> for SessionClose {
    fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, ql_codec::Error> {
        Ok(Self {
            code: reader.decode()?,
        })
    }
}

impl Encode for SessionClose {
    fn encoded_len(&self) -> usize {
        self.code.encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.code.encode(out);
    }
}
