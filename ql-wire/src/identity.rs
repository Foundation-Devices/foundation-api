use crate::{MlDsaPrivateKey, MlDsaPublicKey, MlKemPrivateKey, MlKemPublicKey, XID};

#[derive(Debug, Clone)]
pub struct QlIdentity {
    pub xid: XID,
    pub signing_private_key: MlDsaPrivateKey,
    pub signing_public_key: MlDsaPublicKey,
    pub encapsulation_private_key: MlKemPrivateKey,
    pub encapsulation_public_key: MlKemPublicKey,
}

impl QlIdentity {
    pub fn new(
        xid: XID,
        signing_private_key: MlDsaPrivateKey,
        signing_public_key: MlDsaPublicKey,
        encapsulation_private_key: MlKemPrivateKey,
        encapsulation_public_key: MlKemPublicKey,
    ) -> Self {
        Self {
            xid,
            signing_private_key,
            signing_public_key,
            encapsulation_private_key,
            encapsulation_public_key,
        }
    }
}
