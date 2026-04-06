use crate::{
    codec, ByteSlice, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, QlCrypto, WireEncode,
    WireError, XID,
};

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
}

impl WireEncode for PeerBundle {
    fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.version.encode(out);
        self.xid.encode(out);
        self.capabilities.encode(out);
        self.mlkem_public_key.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for PeerBundle {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            version: reader.decode()?,
            xid: reader.decode()?,
            capabilities: reader.decode()?,
            mlkem_public_key: reader.decode()?,
        })
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
