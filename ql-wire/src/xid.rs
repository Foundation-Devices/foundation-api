#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct XID(pub [u8; Self::SIZE]);

impl XID {
    pub const SIZE: usize = 16;
}
