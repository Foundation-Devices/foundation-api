use crate::{codec, XID};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QlHeader {
    pub sender: XID,
    pub recipient: XID,
}

impl QlHeader {
    pub fn aad(&self) -> Vec<u8> {
        codec::header_aad(self)
    }
}
