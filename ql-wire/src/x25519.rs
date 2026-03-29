#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct X25519PrivateKey([u8; Self::SIZE]);

impl X25519PrivateKey {
    pub const SIZE: usize = 32;

    pub const fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(data)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for X25519PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct X25519PublicKey([u8; Self::SIZE]);

impl X25519PublicKey {
    pub const SIZE: usize = 32;

    pub const fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(data)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X25519KeyPair {
    pub private: X25519PrivateKey,
    pub public: X25519PublicKey,
}
