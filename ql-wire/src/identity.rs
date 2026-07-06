use std::ops::Deref;

use codec::LenBytes;
use ql_common::QID;

use crate::{
    codec, derive_qid, ByteSlice, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, QlCrypto, QlHash,
    WireEncode, WireError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerBundle {
    pub version: u16,
    pub qid: QID,
    pub capabilities: u32,
    pub mlkem_public_key: MlKemPublicKey,
    pub name: QlName,
    pub metadata: Box<[u8]>,
}

impl PeerBundle {
    pub const VERSION: u16 = 1;
    pub const FIXED_WIRE_SIZE: usize =
        size_of::<u16>() + QID::SIZE + size_of::<u32>() + MlKemPublicKey::SIZE;
}

impl WireEncode for PeerBundle {
    fn encoded_len(&self) -> usize {
        Self::FIXED_WIRE_SIZE + self.name.encoded_len() + LenBytes(&*self.metadata).encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.version.encode(out);
        self.qid.encode(out);
        self.capabilities.encode(out);
        self.mlkem_public_key.encode(out);
        self.name.encode(out);
        LenBytes(&*self.metadata).encode(out);
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
            metadata: reader
                .decode::<LenBytes<B>>()?
                .0
                .to_vec()
                .into_boxed_slice(),
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
    pub metadata: Box<[u8]>,
}

impl QlIdentity {
    pub const FIXED_WIRE_SIZE: usize =
        QID::SIZE + MlKemPrivateKey::SIZE + MlKemPublicKey::SIZE + size_of::<u32>();

    pub fn new(
        crypto: &impl QlHash,
        mlkem_private_key: MlKemPrivateKey,
        mlkem_public_key: MlKemPublicKey,
        name: impl Into<String>,
    ) -> Self {
        let name = QlName(name.into());
        let qid = derive_qid(crypto, &mlkem_public_key);
        Self {
            qid,
            mlkem_private_key,
            mlkem_public_key,
            capabilities: 0,
            name,
            metadata: Box::default(),
        }
    }

    pub fn with_metadata(mut self, metadata: impl Into<Box<[u8]>>) -> Self {
        self.metadata = metadata.into();
        self
    }

    pub fn bundle(&self) -> PeerBundle {
        PeerBundle {
            version: PeerBundle::VERSION,
            qid: self.qid,
            capabilities: self.capabilities,
            mlkem_public_key: self.mlkem_public_key.clone(),
            name: self.name.clone(),
            metadata: self.metadata.clone(),
        }
    }
}

impl WireEncode for QlIdentity {
    fn encoded_len(&self) -> usize {
        Self::FIXED_WIRE_SIZE + self.name.encoded_len() + LenBytes(&*self.metadata).encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.qid.encode(out);
        self.mlkem_private_key.as_bytes().encode(out);
        self.mlkem_public_key.encode(out);
        self.capabilities.encode(out);
        self.name.encode(out);
        LenBytes(&*self.metadata).encode(out);
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
            metadata: reader
                .decode::<LenBytes<B>>()?
                .0
                .to_vec()
                .into_boxed_slice(),
        })
    }
}

pub fn generate_identity(crypto: &impl QlCrypto, name: impl Into<String>) -> QlIdentity {
    let MlKemKeyPair { private, public } = crypto.mlkem_generate_keypair();
    QlIdentity::new(crypto, private, public, name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QlName(pub String);

impl Deref for QlName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl WireEncode for QlName {
    fn encoded_len(&self) -> usize {
        LenBytes(self.0.as_bytes()).encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        LenBytes(self.0.as_bytes()).encode(out)
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for QlName {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        let bytes = reader.decode::<LenBytes<B>>()?.0;
        let name = std::str::from_utf8(&bytes).map_err(|_| WireError::InvalidPayload)?;
        Ok(QlName(name.into()))
    }
}
