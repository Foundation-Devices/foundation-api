//! quantum link protocol wire format

mod codec;
mod control;
mod encrypted;
mod encrypted_message;
mod error;
mod handshake;
mod header;
mod identity;
mod nonce;
mod pair;
mod pq;
mod record;
mod xid;

pub use control::*;
pub use encrypted::*;
pub use encrypted_message::*;
pub use error::*;
pub use handshake::*;
pub use header::*;
pub use identity::*;
pub use nonce::*;
pub use pair::*;
pub use pq::*;
pub use record::*;
pub use xid::*;

pub const QL_WIRE_VERSION: u8 = 1;

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
