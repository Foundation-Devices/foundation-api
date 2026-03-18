//! quantum link protocol wire format

mod codec;
pub mod control;
pub mod encrypted;
pub mod encrypted_message;
pub mod error;
pub mod handshake;
pub mod header;
pub mod identity;
pub mod nonce;
pub mod pair;
mod pq;
pub mod record;
pub mod xid;

pub use control::{ControlId, ControlMeta};
pub use encrypted::{
    close::SessionCloseBody, CloseCode, CloseTarget, SessionAck, SessionBody, SessionEnvelope,
    SessionSeq, StreamChunk, StreamClose, StreamId,
};
pub use encrypted_message::{EncryptedMessage, EncryptedMessageRef};
pub use error::WireError;
pub use header::QlHeader;
pub use identity::QlIdentity;
pub use nonce::Nonce;
pub use pq::{
    generate_ml_dsa_keypair, generate_ml_kem_keypair, MlDsaPrivateKey, MlDsaPublicKey,
    MlDsaSignature, MlKemCiphertext, MlKemPrivateKey, MlKemPublicKey, SessionKey,
};
pub use record::{QlPayload, QlPayloadRef, QlRecord, QlRecordRef};
pub use xid::XID;

pub trait QlCrypto {
    fn fill_random_bytes(&self, data: &mut [u8]);

    fn hash(&self, parts: &[&[u8]]) -> [u8; 32];

    fn encrypt_with_aead(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Option<[u8; EncryptedMessage::AUTH_SIZE]>;

    fn decrypt_with_aead(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        auth_tag: &[u8; EncryptedMessage::AUTH_SIZE],
    ) -> bool;
}

#[cfg(test)]
mod tests;
