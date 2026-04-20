use libcrux_aesgcm::AesGcm256Key;
use libcrux_ml_kem::mlkem1024;
use sha2::{Digest, Sha256};

use crate::{
    MlKemCiphertext, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, Nonce, QlAead, QlCrypto,
    QlHash, QlIdentity, QlKem, QlRandom, SessionKey, ENCRYPTED_MESSAGE_AUTH_SIZE, XID,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct SoftwareCrypto;

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopCrypto;

pub fn test_identity(crypto: &impl QlCrypto) -> QlIdentity {
    crate::generate_identity(crypto, XID(random_array(crypto)))
}

pub fn test_identities(crypto: &impl QlCrypto) -> (QlIdentity, QlIdentity) {
    (test_identity(crypto), test_identity(crypto))
}

impl QlRandom for SoftwareCrypto {
    fn fill_random_bytes(&self, out: &mut [u8]) {
        getrandom::getrandom(out).unwrap();
    }
}

impl QlHash for SoftwareCrypto {
    fn sha256(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().into()
    }
}

impl QlAead for SoftwareCrypto {
    type B = Vec<u8>;

    fn aes256_gcm_encrypt(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        mut buffer: Self::B,
        range: core::ops::Range<usize>,
    ) -> (Self::B, [u8; ENCRYPTED_MESSAGE_AUTH_SIZE]) {
        let key: AesGcm256Key = (*key.data()).into();
        let plaintext = buffer[range.clone()].to_vec();
        let mut auth = [0u8; ENCRYPTED_MESSAGE_AUTH_SIZE];
        key.encrypt(
            &mut buffer[range],
            (&mut auth).into(),
            (&nonce.0).into(),
            aad,
            &plaintext,
        )
        .unwrap();
        (buffer, auth)
    }

    fn aes256_gcm_decrypt(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        mut buffer: Self::B,
        range: core::ops::Range<usize>,
        auth_tag: &[u8; ENCRYPTED_MESSAGE_AUTH_SIZE],
    ) -> Option<Self::B> {
        let key: AesGcm256Key = (*key.data()).into();
        let ciphertext = buffer[range.clone()].to_vec();
        key.decrypt(
            &mut buffer[range],
            (&nonce.0).into(),
            aad,
            &ciphertext,
            auth_tag.into(),
        )
        .ok()?;
        Some(buffer)
    }
}

impl QlKem for SoftwareCrypto {
    fn mlkem_generate_keypair(&self) -> MlKemKeyPair {
        let key_pair = mlkem1024::generate_key_pair(random_array(self));
        let mut public = [0u8; MlKemPublicKey::SIZE];
        public.copy_from_slice(key_pair.pk());
        let mut private = [0u8; MlKemPrivateKey::SIZE];
        private.copy_from_slice(key_pair.sk());

        MlKemKeyPair {
            private: MlKemPrivateKey::new(Box::new(private)),
            public: MlKemPublicKey::new(Box::new(public)),
        }
    }

    fn mlkem_encapsulate(&self, public_key: &MlKemPublicKey) -> (MlKemCiphertext, SessionKey) {
        let public_key = public_key.as_bytes().into();
        let (ciphertext_value, shared_value) =
            mlkem1024::encapsulate(&public_key, random_array(self));
        let mut ciphertext = [0u8; MlKemCiphertext::SIZE];
        ciphertext.copy_from_slice(ciphertext_value.as_slice());
        let mut shared = [0u8; SessionKey::SIZE];
        shared.copy_from_slice(shared_value.as_slice());
        (
            MlKemCiphertext::new(Box::new(ciphertext)),
            SessionKey::from_data(shared),
        )
    }

    fn mlkem_decapsulate(
        &self,
        private_key: &MlKemPrivateKey,
        ciphertext: &MlKemCiphertext,
    ) -> SessionKey {
        let private_key = private_key.as_bytes().into();
        let ciphertext = ciphertext.as_bytes().into();
        let shared = mlkem1024::decapsulate(&private_key, &ciphertext);
        let mut out = [0u8; SessionKey::SIZE];
        out.copy_from_slice(shared.as_slice());
        SessionKey::from_data(out)
    }
}

impl QlRandom for NoopCrypto {
    fn fill_random_bytes(&self, out: &mut [u8]) {
        out.fill(0);
    }
}

impl QlHash for NoopCrypto {
    fn sha256(&self, _parts: &[&[u8]]) -> [u8; 32] {
        [0; 32]
    }
}

impl QlAead for NoopCrypto {
    type B = Vec<u8>;

    fn aes256_gcm_encrypt(
        &self,
        _key: &SessionKey,
        _nonce: &Nonce,
        _aad: &[u8],
        buffer: Self::B,
        _range: core::ops::Range<usize>,
    ) -> (Self::B, [u8; ENCRYPTED_MESSAGE_AUTH_SIZE]) {
        (buffer, [0; ENCRYPTED_MESSAGE_AUTH_SIZE])
    }

    fn aes256_gcm_decrypt(
        &self,
        _key: &SessionKey,
        _nonce: &Nonce,
        _aad: &[u8],
        _buffer: Self::B,
        _range: core::ops::Range<usize>,
        _auth_tag: &[u8; ENCRYPTED_MESSAGE_AUTH_SIZE],
    ) -> Option<Self::B> {
        None
    }
}

impl QlKem for NoopCrypto {
    fn mlkem_generate_keypair(&self) -> MlKemKeyPair {
        MlKemKeyPair {
            private: MlKemPrivateKey::new(Box::new([0; MlKemPrivateKey::SIZE])),
            public: MlKemPublicKey::new(Box::new([0; MlKemPublicKey::SIZE])),
        }
    }

    fn mlkem_encapsulate(&self, _public_key: &MlKemPublicKey) -> (MlKemCiphertext, SessionKey) {
        (
            MlKemCiphertext::new(Box::new([0; MlKemCiphertext::SIZE])),
            SessionKey::from_data([0; SessionKey::SIZE]),
        )
    }

    fn mlkem_decapsulate(
        &self,
        _private_key: &MlKemPrivateKey,
        _ciphertext: &MlKemCiphertext,
    ) -> SessionKey {
        SessionKey::from_data([0; SessionKey::SIZE])
    }
}

fn random_array<const L: usize>(crypto: &impl QlRandom) -> [u8; L] {
    let mut out = [0u8; L];
    crypto.fill_random_bytes(&mut out);
    out
}
