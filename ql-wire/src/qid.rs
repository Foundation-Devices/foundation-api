use crate::{MlKemPublicKey, QlHash, ML_KEM_SUITE_TAG, QID};

array_wrapper_codec!(QID);

pub fn derive_qid(crypto: &impl QlHash, mlkem_public_key: &MlKemPublicKey) -> QID {
    let digest = crypto.sha256(&[
        b"quantum-link qid v1",
        ML_KEM_SUITE_TAG,
        mlkem_public_key.as_bytes(),
    ]);
    let mut qid = [0u8; QID::SIZE];
    qid.copy_from_slice(&digest[..QID::SIZE]);
    QID(qid)
}
