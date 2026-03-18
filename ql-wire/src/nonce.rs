#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Nonce(pub [u8; Self::SIZE]);

impl Nonce {
    pub const SIZE: usize = 12;
}
