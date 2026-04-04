use crate::{codec, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, QlCrypto, WireError, XID};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerBundle {
    pub version: u16,
    pub xid: XID,
    pub capabilities: u32,
    pub mlkem_public_key: MlKemPublicKey,
}

impl PeerBundle {
    pub const VERSION: u16 = 1;
    pub const WIRE_SIZE: usize =
        size_of::<u16>() + XID::SIZE + size_of::<u32>() + MlKemPublicKey::SIZE;

    pub fn encode_into<'a>(&self, out: &'a mut [u8]) -> &'a mut [u8] {
        let out = codec::write_u16(out, self.version);
        let out = codec::write_bytes(out, &self.xid.0);
        let out = codec::write_u32(out, self.capabilities);
        codec::write_bytes(out, self.mlkem_public_key.as_bytes())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0; Self::WIRE_SIZE];
        let _ = self.encode_into(&mut out);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let bundle = Self {
            version: reader.take_u16()?,
            xid: XID(reader.take_array()?),
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

    #[must_use]
    pub fn with_capabilities(mut self, capabilities: u32) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn bundle(&self) -> PeerBundle {
        PeerBundle {
            version: PeerBundle::VERSION,
            xid: self.xid,
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
