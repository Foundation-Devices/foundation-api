use crate::{codec, ByteSlice, WireEncode, WireError};

pub const ML_KEM_SUITE_TAG: &[u8] = b"ml-kem-1024";

// ql-wire fixes the protocol to ML-KEM-1024 on the wire, but the host
// platform is free to satisfy QlKem with any backend that produces the same
// serialized sizes.
const ML_KEM_1024_SHARED_SECRET_SIZE: usize = 32;
const ML_KEM_1024_PUBLIC_KEY_SIZE: usize = 1568;
const ML_KEM_1024_PRIVATE_KEY_SIZE: usize = 3168;
const ML_KEM_1024_CIPHERTEXT_SIZE: usize = 1568;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey([u8; Self::SIZE]);

impl SessionKey {
    pub const SIZE: usize = ML_KEM_1024_SHARED_SECRET_SIZE;

    pub const fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(data)
    }

    pub const fn data(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for SessionKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl WireEncode for SessionKey {
    fn encoded_len(&self) -> usize {
        Self::SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for SessionKey {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self::from_data(reader.decode()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MlKemPublicKey(Box<[u8; MlKemPublicKey::SIZE]>);

impl MlKemPublicKey {
    pub const SIZE: usize = ML_KEM_1024_PUBLIC_KEY_SIZE;

    pub fn new(data: Box<[u8; Self::SIZE]>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        self.0.as_ref()
    }
}

impl Drop for MlKemPublicKey {
    fn drop(&mut self) {
        self.0.as_mut().fill(0);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for MlKemPublicKey {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self::new(reader.decode()?))
    }
}

impl WireEncode for MlKemPublicKey {
    fn encoded_len(&self) -> usize {
        Self::SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.as_ref().encode(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MlKemPrivateKey(Box<[u8; MlKemPrivateKey::SIZE]>);

impl MlKemPrivateKey {
    pub const SIZE: usize = ML_KEM_1024_PRIVATE_KEY_SIZE;

    pub fn new(data: Box<[u8; Self::SIZE]>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        self.0.as_ref()
    }
}

impl Drop for MlKemPrivateKey {
    fn drop(&mut self) {
        self.0.as_mut().fill(0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MlKemCiphertext(Box<[u8; MlKemCiphertext::SIZE]>);

impl MlKemCiphertext {
    pub const SIZE: usize = ML_KEM_1024_CIPHERTEXT_SIZE;

    pub fn new(data: Box<[u8; Self::SIZE]>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        self.0.as_ref()
    }
}

impl Drop for MlKemCiphertext {
    fn drop(&mut self) {
        self.0.as_mut().fill(0);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for MlKemCiphertext {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self::new(reader.decode()?))
    }
}

impl WireEncode for MlKemCiphertext {
    fn encoded_len(&self) -> usize {
        Self::SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.as_ref().encode(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MlKemKeyPair {
    pub private: MlKemPrivateKey,
    pub public: MlKemPublicKey,
}
