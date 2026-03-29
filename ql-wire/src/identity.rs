use crate::{codec, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, QlCrypto, WireError, XID};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerBundle {
    pub version: u16,
    pub capabilities: u32,
    pub mlkem_public_key: MlKemPublicKey,
}

impl PeerBundle {
    pub const VERSION: u16 = 1;
    pub const ENCODED_LEN: usize =
        core::mem::size_of::<u16>() + core::mem::size_of::<u32>() + MlKemPublicKey::SIZE;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        codec::push_u16(out, self.version);
        codec::push_u32(out, self.capabilities);
        codec::push_bytes(out, self.mlkem_public_key.as_bytes());
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        self.encode_into(&mut out);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let bundle = Self {
            version: reader.take_u16()?,
            capabilities: reader.take_u32()?,
            mlkem_public_key: MlKemPublicKey::from_data(reader.take_array()?),
        };
        reader.finish()?;
        Ok(bundle)
    }
}

#[derive(Debug, Clone)]
pub struct QlIdentity {
    pub xid: XID,
    pub mlkem_private_key: MlKemPrivateKey,
    pub mlkem_public_key: MlKemPublicKey,
    pub capabilities: u32,
}

impl QlIdentity {
    pub fn new(
        xid: XID,
        mlkem_private_key: MlKemPrivateKey,
        mlkem_public_key: MlKemPublicKey,
    ) -> Self {
        Self {
            xid,
            mlkem_private_key,
            mlkem_public_key,
            capabilities: 0,
        }
    }

    pub fn with_capabilities(mut self, capabilities: u32) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn bundle(&self) -> PeerBundle {
        PeerBundle {
            version: PeerBundle::VERSION,
            capabilities: self.capabilities,
            mlkem_public_key: self.mlkem_public_key.clone(),
        }
    }
}

pub fn generate_identity(crypto: &impl QlCrypto, xid: XID) -> QlIdentity {
    let MlKemKeyPair {
        private: mlkem_private_key,
        public: mlkem_public_key,
    } = crypto.mlkem_generate_keypair();
    QlIdentity::new(xid, mlkem_private_key, mlkem_public_key)
}
