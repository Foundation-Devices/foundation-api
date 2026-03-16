use bc_components::{
    MLDSAPrivateKey, MLDSAPublicKey, MLKEMPrivateKey, MLKEMPublicKey, SigningPublicKey, XID,
};

#[derive(Debug, Clone)]
pub struct QlIdentity {
    pub xid: XID,
    pub signing_private_key: MLDSAPrivateKey,
    pub signing_public_key: MLDSAPublicKey,
    pub encapsulation_private_key: MLKEMPrivateKey,
    pub encapsulation_public_key: MLKEMPublicKey,
}

impl QlIdentity {
    pub fn from_keys(
        signing_private_key: MLDSAPrivateKey,
        signing_public_key: MLDSAPublicKey,
        encapsulation_private_key: MLKEMPrivateKey,
        encapsulation_public_key: MLKEMPublicKey,
    ) -> Self {
        Self {
            xid: XID::new(SigningPublicKey::MLDSA(signing_public_key.clone())),
            signing_private_key,
            signing_public_key,
            encapsulation_private_key,
            encapsulation_public_key,
        }
    }
}
