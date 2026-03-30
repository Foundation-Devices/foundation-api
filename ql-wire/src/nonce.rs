#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Nonce(pub [u8; Self::SIZE]);

impl Nonce {
    pub const SIZE: usize = 12;

    pub fn from_counter(counter: u64) -> Self {
        let mut nonce = [0u8; Self::SIZE];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        Self(nonce)
    }
}
