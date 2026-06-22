use crate::{MlKemPublicKey, QlHash, ML_KEM_SUITE_TAG};

crate::array_wrapper!(QID, 16);

impl QID {
    pub fn derive(crypto: &impl QlHash, mlkem_public_key: &MlKemPublicKey) -> Self {
        let digest = crypto.sha256(&[
            b"quantum-link qid v1",
            ML_KEM_SUITE_TAG,
            mlkem_public_key.as_bytes(),
        ]);
        let mut qid = [0u8; Self::SIZE];
        qid.copy_from_slice(&digest[..Self::SIZE]);
        Self(qid)
    }
}
