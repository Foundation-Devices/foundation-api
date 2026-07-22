use ql_common::QID;

use crate::{derive_qid, Error, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, QlCrypto, QlHash};

ql_codec::codec! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PeerBundle {
        pub version: u16,
        pub qid: QID,
        pub capabilities: u32,
        pub mlkem_public_key: MlKemPublicKey,
        pub name: String,
    }
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

ql_codec::codec! {
    #[derive(Debug, Clone)]
    pub struct QlIdentity {
        pub qid: QID,
        pub mlkem_private_key: MlKemPrivateKey,
        pub mlkem_public_key: MlKemPublicKey,
        pub capabilities: u32,
        pub name: String,
    }
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

pub fn generate_identity(crypto: &impl QlCrypto, name: impl Into<String>) -> QlIdentity {
    let MlKemKeyPair { private, public } = crypto.mlkem_generate_keypair();
    QlIdentity::new(crypto, private, public, name)
}
