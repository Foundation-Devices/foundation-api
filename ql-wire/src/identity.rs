use std::ops::Deref;

use crate::{
    codec, ByteSlice, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, QlCrypto, QlHash, VarInt,
    WireEncode, WireError, QID,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerBundle {
    pub version: u16,
    pub qid: QID,
    pub capabilities: u32,
    pub mlkem_public_key: MlKemPublicKey,
    pub name: QlName,
}

impl PeerBundle {
    pub const VERSION: u16 = 1;
    pub const FIXED_WIRE_SIZE: usize =
        size_of::<u16>() + QID::SIZE + size_of::<u32>() + MlKemPublicKey::SIZE;
    pub const MAX_WIRE_SIZE: usize = Self::FIXED_WIRE_SIZE + VarInt::MAX_SIZE + QlName::MAX_LEN;

    pub fn qid_matches_public_key(&self, crypto: &impl QlHash) -> bool {
        self.qid.matches_public_key(crypto, &self.mlkem_public_key)
    }
}

impl WireEncode for PeerBundle {
    fn encoded_len(&self) -> usize {
        Self::FIXED_WIRE_SIZE + self.name.encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.version.encode(out);
        self.qid.encode(out);
        self.capabilities.encode(out);
        self.mlkem_public_key.encode(out);
        self.name.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for PeerBundle {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            version: reader.decode()?,
            qid: reader.decode()?,
            capabilities: reader.decode()?,
            mlkem_public_key: reader.decode()?,
            name: reader.decode()?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct QlIdentity {
    pub qid: QID,
    pub mlkem_private_key: MlKemPrivateKey,
    pub mlkem_public_key: MlKemPublicKey,
    pub capabilities: u32,
    pub name: QlName,
}

impl QlIdentity {
    pub const FIXED_WIRE_SIZE: usize =
        QID::SIZE + MlKemPrivateKey::SIZE + MlKemPublicKey::SIZE + size_of::<u32>();
    pub const MAX_WIRE_SIZE: usize = Self::FIXED_WIRE_SIZE + VarInt::MAX_SIZE + QlName::MAX_LEN;

    pub fn new(
        crypto: &impl QlHash,
        mlkem_private_key: MlKemPrivateKey,
        mlkem_public_key: MlKemPublicKey,
        name: impl Into<String>,
    ) -> Result<Self, WireError> {
        let name = QlName::new(name)?;
        let qid = QID::derive(crypto, &mlkem_public_key);
        Ok(Self {
            qid,
            mlkem_private_key,
            mlkem_public_key,
            capabilities: 0,
            name,
        })
    }

    #[must_use]
    pub fn with_capabilities(mut self, capabilities: u32) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Result<Self, WireError> {
        self.name = QlName::new(name)?;
        Ok(self)
    }

    pub fn bundle(&self) -> PeerBundle {
        PeerBundle {
            version: PeerBundle::VERSION,
            qid: self.qid,
            capabilities: self.capabilities,
            mlkem_public_key: self.mlkem_public_key.clone(),
            name: self.name.clone(),
        }
    }
}

impl WireEncode for QlIdentity {
    fn encoded_len(&self) -> usize {
        Self::FIXED_WIRE_SIZE + self.name.encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.qid.encode(out);
        self.mlkem_private_key.as_bytes().encode(out);
        self.mlkem_public_key.encode(out);
        self.capabilities.encode(out);
        self.name.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for QlIdentity {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            qid: reader.decode()?,
            mlkem_private_key: MlKemPrivateKey::new(reader.decode()?),
            mlkem_public_key: reader.decode()?,
            capabilities: reader.decode()?,
            name: reader.decode()?,
        })
    }
}

pub fn generate_identity(
    crypto: &impl QlCrypto,
    name: impl Into<String>,
) -> Result<QlIdentity, WireError> {
    let MlKemKeyPair {
        private: mlkem_private_key,
        public: mlkem_public_key,
    } = crypto.mlkem_generate_keypair();
    QlIdentity::new(crypto, mlkem_private_key, mlkem_public_key, name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QlName(String);

impl QlName {
    pub const MAX_LEN: usize = 256;

    pub fn new(name: impl Into<String>) -> Result<Self, WireError> {
        let name = name.into();
        if name.is_empty() || name.len() > Self::MAX_LEN {
            return Err(WireError::InvalidPayload);
        }
        Ok(Self(name))
    }
}

impl Deref for QlName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl WireEncode for QlName {
    fn encoded_len(&self) -> usize {
        let len = VarInt::try_from(self.0.len()).unwrap();
        len.encoded_len() + self.0.len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        VarInt::try_from(self.0.len())
            .expect("identity name length fits in varint")
            .encode(out);
        self.0.as_bytes().encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for QlName {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        let len = usize::try_from(reader.decode::<VarInt>()?.into_inner())
            .map_err(|_| WireError::InvalidPayload)?;
        if len == 0 || len > Self::MAX_LEN {
            return Err(WireError::InvalidPayload);
        }
        let bytes = reader.take_bytes(len)?;
        let name = std::str::from_utf8(&bytes).map_err(|_| WireError::InvalidPayload)?;
        QlName::new(name)
    }
}
