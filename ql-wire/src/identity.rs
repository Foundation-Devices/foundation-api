use ql_codec::{ByteSlice, Encode};
use ql_common::QID;

use crate::{derive_qid, Error, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, QlCrypto, QlHash};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerBundle {
    pub version: u16,
    pub qid: QID,
    pub capabilities: u32,
    pub mlkem_public_key: MlKemPublicKey,
    pub name: String,
}

impl PeerBundle {
    pub const VERSION: u16 = 1;

    pub fn validate(&self, crypto: &impl QlHash) -> Result<(), Error> {
        if self.version != Self::VERSION || self.qid != derive_qid(crypto, &self.mlkem_public_key) {
            return Err(Error::InvalidRemoteBundle);
        }
        Ok(())
    }
}

impl Encode for PeerBundle {
    fn encoded_len(&self) -> usize {
        self.version.encoded_len()
            + self.qid.encoded_len()
            + self.capabilities.encoded_len()
            + self.mlkem_public_key.encoded_len()
            + self.name.encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.version.encode(out);
        self.qid.encode(out);
        self.capabilities.encode(out);
        self.mlkem_public_key.encode(out);
        self.name.encode(out);
    }
}

impl<B: ByteSlice> ql_codec::Decode<B> for PeerBundle {
    fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, ql_codec::Error> {
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
    pub name: String,
}

impl QlIdentity {
    pub fn new(
        crypto: &impl QlHash,
        mlkem_private_key: MlKemPrivateKey,
        mlkem_public_key: MlKemPublicKey,
        name: impl Into<String>,
    ) -> Self {
        let qid = derive_qid(crypto, &mlkem_public_key);
        Self {
            qid,
            mlkem_private_key,
            mlkem_public_key,
            capabilities: 0,
            name: name.into(),
        }
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

impl Encode for QlIdentity {
    fn encoded_len(&self) -> usize {
        QID::SIZE
            + MlKemPrivateKey::SIZE
            + MlKemPublicKey::SIZE
            + size_of::<u32>()
            + self.name.encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.qid.encode(out);
        self.mlkem_private_key.as_bytes().encode(out);
        self.mlkem_public_key.encode(out);
        self.capabilities.encode(out);
        self.name.encode(out);
    }
}

impl<B: ByteSlice> ql_codec::Decode<B> for QlIdentity {
    fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, ql_codec::Error> {
        Ok(Self {
            qid: reader.decode()?,
            mlkem_private_key: MlKemPrivateKey::new(reader.decode()?),
            mlkem_public_key: reader.decode()?,
            capabilities: reader.decode()?,
            name: reader.decode()?,
        })
    }
}

pub fn generate_identity(crypto: &impl QlCrypto, name: impl Into<String>) -> QlIdentity {
    let MlKemKeyPair { private, public } = crypto.mlkem_generate_keypair();
    QlIdentity::new(crypto, private, public, name)
}
