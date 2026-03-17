#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct XID(pub [u8; crate::XID_SIZE]);
