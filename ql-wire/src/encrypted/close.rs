use std::mem::size_of;

use super::CloseCode;
use crate::{
    codec::{self, Reader},
    WireError,
};

/// closes the whole session immediately with a close code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClose {
    pub code: CloseCode,
}

impl SessionClose {
    pub const WIRE_SIZE: usize = size_of::<u16>();

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        codec::push_u16(out, self.code.0);
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes);
        let code = reader.take_u16()?;
        Ok(Self {
            code: CloseCode(code),
        })
    }
}
