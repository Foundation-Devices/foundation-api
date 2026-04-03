use crate::{codec, codec::Reader, WireError};

/// closes the whole session immediately with a close code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClose {
    pub code: SessionCloseCode,
}

impl SessionClose {
    pub const WIRE_SIZE: usize = size_of::<SessionCloseCode>();

    pub fn encode_into(&self, out: &mut [u8]) {
        let _ = codec::write_u16(out, self.code.0);
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes);
        let code = reader.take_u16()?;
        Ok(Self {
            code: SessionCloseCode(code),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SessionCloseCode(pub u16);

impl SessionCloseCode {
    pub const CANCELLED: Self = Self(0);
    pub const PROTOCOL: Self = Self(1);
    pub const TIMEOUT: Self = Self(2);
}
