#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Nonce(pub [u8; crate::NONCE_SIZE]);
