#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ServiceId(pub [u8; 16]);

impl ServiceId {
    pub const fn from_bytes(value: [u8; 16]) -> Self {
        Self(value)
    }

    pub const fn into_inner(self) -> [u8; 16] {
        self.0
    }
}

impl From<[u8; 16]> for ServiceId {
    fn from(value: [u8; 16]) -> Self {
        Self::from_bytes(value)
    }
}
