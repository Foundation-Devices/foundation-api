use bc_components::{
    EncapsulationPublicKey, EncapsulationScheme, PrivateKeys, SignatureScheme, SigningPublicKey,
    XID,
};

#[derive(Debug, Clone)]
pub struct QlIdentity {
    pub private_keys: PrivateKeys,
    pub signing_public_key: SigningPublicKey,
    pub encapsulation_public_key: EncapsulationPublicKey,
    pub xid: XID,
}

impl QlIdentity {
    pub fn generate() -> Self {
        let (signing_private_key, signing_public_key) = SignatureScheme::MLDSA44.keypair();
        let (encapsulation_private_key, encapsulation_public_key) =
            EncapsulationScheme::MLKEM512.keypair();
        let private_keys = PrivateKeys::with_keys(signing_private_key, encapsulation_private_key);
        let xid = XID::new(&signing_public_key);
        Self {
            private_keys,
            signing_public_key,
            encapsulation_public_key,
            xid,
        }
    }
}
