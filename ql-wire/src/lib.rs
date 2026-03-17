//! quantum link protocol wire format
//!
//! naming conventions:
//! - *Record - unencrypted messages
//! - *Body - message content after decrypting

use thiserror::Error;

mod codec;
pub mod encrypted;
pub mod encrypted_message;
pub mod handshake;
mod id;
pub mod pair;
mod pq;
mod xid;

pub use encrypted::{
    close::SessionCloseBody,
    stream::{CloseCode, CloseTarget, StreamCloseFrame, StreamFrame},
    SessionAck, SessionBody, SessionEnvelope,
};
pub use encrypted_message::{Nonce, AUTH_SIZE};
pub use id::{ControlId, SessionSeq, StreamId};
pub use pq::{
    generate_ml_dsa_keypair, generate_ml_kem_keypair, MlDsaPrivateKey, MlDsaPublicKey,
    MlDsaSignature, MlKemCiphertext, MlKemPrivateKey, MlKemPublicKey, SessionKey,
};
use rkyv::{Archive, Deserialize, Serialize};
pub use xid::XID;

pub(crate) use self::codec::{access_mut_value, access_value, deserialize_value, encode_value};

#[derive(Debug, Clone)]
pub struct QlIdentity {
    pub xid: XID,
    pub signing_private_key: MlDsaPrivateKey,
    pub signing_public_key: MlDsaPublicKey,
    pub encapsulation_private_key: MlKemPrivateKey,
    pub encapsulation_public_key: MlKemPublicKey,
}

impl QlIdentity {
    pub fn from_keys(
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

pub trait QlCrypto {
    fn fill_random_bytes(&self, data: &mut [u8]);

    fn hash(&self, parts: &[&[u8]]) -> [u8; 32];

    fn encrypt_with_aead(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Option<[u8; AUTH_SIZE]>;

    fn decrypt_with_aead(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        auth_tag: &[u8; AUTH_SIZE],
    ) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WireError {
    #[error("invalid payload")]
    InvalidPayload,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("expired")]
    Expired,
    #[error("signing failed")]
    SigningFailed,
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QlRecord {
    pub header: QlHeader,
    pub payload: QlPayload,
}

impl QlRecord {
    pub fn encode(&self) -> Vec<u8> {
        encode_value(self)
    }

    pub fn access(bytes: &[u8]) -> Result<&ArchivedQlRecord, WireError> {
        access_value(bytes)
    }

    pub fn access_mut(
        bytes: &mut [u8],
    ) -> Result<rkyv::seal::Seal<'_, ArchivedQlRecord>, WireError> {
        access_mut_value(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        deserialize_value(Self::access(bytes)?)
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QlHeader {
    pub sender: XID,
    pub recipient: XID,
}

impl QlHeader {
    pub fn aad(&self) -> Vec<u8> {
        encode_value(self)
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlMeta {
    pub control_id: ControlId,
    pub valid_until: u64,
}

impl From<&ArchivedControlMeta> for ControlMeta {
    fn from(value: &ArchivedControlMeta) -> Self {
        Self {
            control_id: (&value.control_id).into(),
            valid_until: value.valid_until.to_native(),
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum QlPayload {
    Handshake(handshake::HandshakeRecord),
    Pair(pair::PairRequestRecord),
    Encrypted(encrypted_message::EncryptedMessage),
}

pub(crate) fn ensure_not_expired(meta: &ControlMeta, now_seconds: u64) -> Result<(), WireError> {
    if now_seconds > meta.valid_until {
        Err(WireError::Expired)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};

    use libcrux_aesgcm::AesGcm256Key;
    use sha2::{Digest, Sha256};

    use super::*;

    struct TestCrypto(AtomicU8);

    impl TestCrypto {
        fn new(seed: u8) -> Self {
            Self(AtomicU8::new(seed))
        }
    }

    impl QlCrypto for TestCrypto {
        fn fill_random_bytes(&self, data: &mut [u8]) {
            let seed = self.0.fetch_add(1, Ordering::Relaxed);
            for (index, byte) in data.iter_mut().enumerate() {
                *byte = seed.wrapping_add(index as u8);
            }
        }

        fn hash(&self, parts: &[&[u8]]) -> [u8; 32] {
            let mut hasher = Sha256::new();
            for part in parts {
                hasher.update(part);
            }
            hasher.finalize().into()
        }

        fn encrypt_with_aead(
            &self,
            key: &SessionKey,
            nonce: &Nonce,
            aad: &[u8],
            buffer: &mut [u8],
        ) -> Option<[u8; AUTH_SIZE]> {
            let key: AesGcm256Key = (*key.data()).into();
            let plaintext = buffer.to_vec();
            let mut auth = [0u8; AUTH_SIZE];
            key.encrypt(
                buffer,
                (&mut auth).into(),
                (&nonce.0).into(),
                aad,
                &plaintext,
            )
            .ok()?;
            Some(auth)
        }

        fn decrypt_with_aead(
            &self,
            key: &SessionKey,
            nonce: &Nonce,
            aad: &[u8],
            buffer: &mut [u8],
            auth_tag: &[u8; AUTH_SIZE],
        ) -> bool {
            let key: AesGcm256Key = (*key.data()).into();
            let ciphertext = buffer.to_vec();
            key.decrypt(buffer, (&nonce.0).into(), aad, &ciphertext, auth_tag.into())
                .is_ok()
        }
    }

    #[test]
    fn ql_record_round_trip() {
        let crypto = TestCrypto::new(1);
        let header = QlHeader {
            sender: XID([1; XID::XID_SIZE]),
            recipient: XID([2; XID::XID_SIZE]),
        };
        let body = SessionEnvelope {
            seq: SessionSeq(7),
            ack: SessionAck {
                base: SessionSeq(3),
                bitmap: 0b101,
            },
            body: SessionBody::Ping(encrypted::ping::PingBody),
        };
        let record = encrypted::encrypt_record(
            &crypto,
            header.clone(),
            &SessionKey::from_data([7; SessionKey::SIZE]),
            &body,
            Nonce([8; Nonce::NONCE_SIZE]),
        )
        .unwrap();

        let bytes = record.encode();
        let decoded = QlRecord::decode(&bytes).unwrap();
        assert_eq!(decoded.header, header);
        assert!(matches!(decoded.payload, QlPayload::Encrypted(_)));
    }
}
