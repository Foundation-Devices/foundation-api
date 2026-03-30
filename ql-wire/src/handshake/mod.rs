use crate::{
    codec, ConnectionId, HandshakeHeader, HandshakeKind, MlKemCiphertext, MlKemKeyPair,
    MlKemPublicKey, Nonce, PeerBundle, QlCrypto, SessionKey, WireError,
    ENCRYPTED_MESSAGE_AUTH_SIZE,
};

mod kk;
mod meta;
mod xx;

pub use kk::{Kk1, Kk2, KkHandshake, KkMessage};
pub use meta::{HandshakeId, HandshakeMeta};
pub use xx::{Xx1, Xx2, Xx3, Xx4, XxHandshake, XxMessage};

const SHA256_BLOCK_LEN: usize = 64;
const PROTOCOL_XX: &[u8] = b"ql-wire:pq-xx:v1";
const PROTOCOL_KK: &[u8] = b"ql-wire:pq-kk:v1";
const CONNECTION_ID_DOMAIN: &[u8] = b"ql-wire:conn-id:v1";
const HANDSHAKE_PREAMBLE_DOMAIN: &[u8] = b"ql-wire:handshake-preamble:v1";

pub const ENCRYPTED_MLKEM_CIPHERTEXT_LEN: usize =
    MlKemCiphertext::SIZE + ENCRYPTED_MESSAGE_AUTH_SIZE;
pub const ENCRYPTED_PEER_BUNDLE_LEN: usize = PeerBundle::ENCODED_LEN + ENCRYPTED_MESSAGE_AUTH_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralPublicKey {
    pub mlkem_public_key: MlKemPublicKey,
}

impl EphemeralPublicKey {
    pub const ENCODED_LEN: usize = MlKemPublicKey::SIZE;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        codec::push_bytes(out, self.mlkem_public_key.as_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let value = Self {
            mlkem_public_key: MlKemPublicKey::from_data(reader.take_array()?),
        };
        reader.finish()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMlKemCiphertext(Box<[u8; ENCRYPTED_MLKEM_CIPHERTEXT_LEN]>);

impl EncryptedMlKemCiphertext {
    pub fn from_data(data: [u8; ENCRYPTED_MLKEM_CIPHERTEXT_LEN]) -> Self {
        Self(Box::new(data))
    }

    pub fn as_bytes(&self) -> &[u8; ENCRYPTED_MLKEM_CIPHERTEXT_LEN] {
        self.0.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPeerBundle(Box<[u8; ENCRYPTED_PEER_BUNDLE_LEN]>);

impl EncryptedPeerBundle {
    pub fn from_data(data: [u8; ENCRYPTED_PEER_BUNDLE_LEN]) -> Self {
        Self(Box::new(data))
    }

    pub fn as_bytes(&self) -> &[u8; ENCRYPTED_PEER_BUNDLE_LEN] {
        self.0.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedHandshake {
    pub tx_key: SessionKey,
    pub rx_key: SessionKey,
    pub tx_connection_id: ConnectionId,
    pub rx_connection_id: ConnectionId,
    pub handshake_hash: [u8; 32],
    pub remote_bundle: PeerBundle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

#[derive(Debug, Clone)]
struct EphemeralKeyPair {
    mlkem: MlKemKeyPair,
}

impl EphemeralKeyPair {
    fn public(&self) -> EphemeralPublicKey {
        EphemeralPublicKey {
            mlkem_public_key: self.mlkem.public.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct CipherState {
    key: Option<SessionKey>,
    nonce: u64,
}

impl CipherState {
    fn new() -> Self {
        Self {
            key: None,
            nonce: 0,
        }
    }

    fn initialize_key(&mut self, key: SessionKey) {
        self.key = Some(key);
        self.nonce = 0;
    }

    fn has_key(&self) -> bool {
        self.key.is_some()
    }

    fn encrypt(
        &mut self,
        crypto: &impl QlCrypto,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, WireError> {
        let key = self.key.as_ref().ok_or(WireError::InvalidState)?;
        let nonce = Nonce::from_counter(self.nonce);
        let mut ciphertext = plaintext.to_vec();
        let auth = crypto.aes256_gcm_encrypt(key, &nonce, aad, &mut ciphertext);
        self.nonce = self.nonce.wrapping_add(1);
        ciphertext.extend_from_slice(&auth);
        Ok(ciphertext)
    }

    fn decrypt(
        &mut self,
        crypto: &impl QlCrypto,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, WireError> {
        if ciphertext.len() < ENCRYPTED_MESSAGE_AUTH_SIZE {
            return Err(WireError::InvalidPayload);
        }
        let split = ciphertext.len() - ENCRYPTED_MESSAGE_AUTH_SIZE;
        let (ciphertext, auth) = ciphertext.split_at(split);
        let mut plaintext = ciphertext.to_vec();
        let key = self.key.as_ref().ok_or(WireError::InvalidState)?;
        let nonce = Nonce::from_counter(self.nonce);
        let mut auth_tag = [0u8; ENCRYPTED_MESSAGE_AUTH_SIZE];
        auth_tag.copy_from_slice(auth);
        if !crypto.aes256_gcm_decrypt(key, &nonce, aad, &mut plaintext, &auth_tag) {
            return Err(WireError::DecryptFailed);
        }
        self.nonce = self.nonce.wrapping_add(1);
        Ok(plaintext)
    }
}

#[derive(Debug, Clone)]
struct SymmetricState {
    chaining_key: [u8; 32],
    handshake_hash: [u8; 32],
    cipher: CipherState,
}

impl SymmetricState {
    fn new(crypto: &impl QlCrypto, protocol_name: &[u8]) -> Self {
        let h = crypto.sha256(&[protocol_name]);
        Self {
            chaining_key: h,
            handshake_hash: h,
            cipher: CipherState::new(),
        }
    }

    fn mix_hash(&mut self, crypto: &impl QlCrypto, data: &[u8]) {
        self.handshake_hash = crypto.sha256(&[&self.handshake_hash, data]);
    }

    fn mix_key(&mut self, crypto: &impl QlCrypto, input_key_material: &[u8]) {
        let (chaining_key, cipher_key) = hkdf2(crypto, &self.chaining_key, input_key_material);
        self.chaining_key = chaining_key;
        self.cipher.initialize_key(cipher_key);
    }

    fn mix_key_and_hash(&mut self, crypto: &impl QlCrypto, input_key_material: &[u8]) {
        let (chaining_key, hash_input, cipher_key) =
            hkdf3(crypto, &self.chaining_key, input_key_material);
        self.chaining_key = chaining_key;
        self.mix_hash(crypto, &hash_input);
        self.cipher.initialize_key(cipher_key);
    }

    fn encrypt_and_hash(
        &mut self,
        crypto: &impl QlCrypto,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, WireError> {
        if self.cipher.has_key() {
            let ciphertext = self
                .cipher
                .encrypt(crypto, &self.handshake_hash, plaintext)?;
            self.mix_hash(crypto, &ciphertext);
            Ok(ciphertext)
        } else {
            self.mix_hash(crypto, plaintext);
            Ok(plaintext.to_vec())
        }
    }

    fn decrypt_and_hash(
        &mut self,
        crypto: &impl QlCrypto,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, WireError> {
        if self.cipher.has_key() {
            let plaintext = self
                .cipher
                .decrypt(crypto, &self.handshake_hash, ciphertext)?;
            self.mix_hash(crypto, ciphertext);
            Ok(plaintext)
        } else {
            self.mix_hash(crypto, ciphertext);
            Ok(ciphertext.to_vec())
        }
    }

    fn split_for_role(&self, crypto: &impl QlCrypto, role: Role) -> (SessionKey, SessionKey) {
        let temp_key = hmac_sha256(crypto, &self.chaining_key, &[&[]]);
        let k1 = SessionKey::from_data(hmac_sha256(crypto, &temp_key, &[&[1]]));
        let k2 = SessionKey::from_data(hmac_sha256(crypto, &temp_key, &[k1.as_bytes(), &[2]]));
        match role {
            Role::Initiator => (k1, k2),
            Role::Responder => (k2, k1),
        }
    }
}

fn init_kk_symmetric(
    crypto: &impl QlCrypto,
    initiator_bundle: &PeerBundle,
    responder_bundle: &PeerBundle,
) -> SymmetricState {
    let mut symmetric = SymmetricState::new(crypto, PROTOCOL_KK);
    symmetric.mix_hash(crypto, &initiator_bundle.encode());
    symmetric.mix_hash(crypto, &responder_bundle.encode());
    symmetric
}

fn generate_ephemeral_keypair(crypto: &impl QlCrypto) -> EphemeralKeyPair {
    EphemeralKeyPair {
        mlkem: crypto.mlkem_generate_keypair(),
    }
}

fn mix_hash_ephemeral(
    symmetric: &mut SymmetricState,
    crypto: &impl QlCrypto,
    public: &EphemeralPublicKey,
) {
    symmetric.mix_hash(crypto, public.mlkem_public_key.as_bytes());
}

fn mix_hash_handshake(
    symmetric: &mut SymmetricState,
    crypto: &impl QlCrypto,
    header: HandshakeHeader,
    kind: HandshakeKind,
    meta: &HandshakeMeta,
) {
    let mut encoded_header = Vec::with_capacity(HandshakeHeader::ENCODED_LEN);
    header.encode_into(&mut encoded_header);
    let encoded = meta.encode();
    symmetric.mix_hash(crypto, HANDSHAKE_PREAMBLE_DOMAIN);
    symmetric.mix_hash(crypto, &encoded_header);
    symmetric.mix_hash(crypto, &[kind as u8]);
    symmetric.mix_hash(crypto, &encoded);
}

fn initialize_handshake_meta(
    expected: &mut Option<HandshakeMeta>,
    meta: HandshakeMeta,
) -> Result<(), WireError> {
    match expected {
        Some(stored) if *stored != meta => Err(WireError::InvalidPayload),
        Some(_) => Ok(()),
        None => {
            *expected = Some(meta);
            Ok(())
        }
    }
}

fn require_handshake_meta(
    expected: &Option<HandshakeMeta>,
    meta: HandshakeMeta,
) -> Result<(), WireError> {
    match expected {
        Some(stored) if *stored == meta => Ok(()),
        _ => Err(WireError::InvalidPayload),
    }
}

fn encrypt_peer_bundle(
    crypto: &impl QlCrypto,
    symmetric: &mut SymmetricState,
    bundle: &PeerBundle,
) -> Result<EncryptedPeerBundle, WireError> {
    let ciphertext = symmetric.encrypt_and_hash(crypto, &bundle.encode())?;
    if ciphertext.len() != ENCRYPTED_PEER_BUNDLE_LEN {
        return Err(WireError::InvalidState);
    }
    let mut out = [0u8; ENCRYPTED_PEER_BUNDLE_LEN];
    out.copy_from_slice(&ciphertext);
    Ok(EncryptedPeerBundle::from_data(out))
}

fn decrypt_peer_bundle(
    crypto: &impl QlCrypto,
    symmetric: &mut SymmetricState,
    bundle: &EncryptedPeerBundle,
) -> Result<PeerBundle, WireError> {
    let plaintext = symmetric.decrypt_and_hash(crypto, bundle.as_bytes())?;
    PeerBundle::decode(&plaintext)
}

fn encrypt_mlkem_ciphertext(
    crypto: &impl QlCrypto,
    symmetric: &mut SymmetricState,
    ciphertext: &MlKemCiphertext,
) -> Result<EncryptedMlKemCiphertext, WireError> {
    let encrypted = symmetric.encrypt_and_hash(crypto, ciphertext.as_bytes())?;
    if encrypted.len() != ENCRYPTED_MLKEM_CIPHERTEXT_LEN {
        return Err(WireError::InvalidState);
    }
    let mut out = [0u8; ENCRYPTED_MLKEM_CIPHERTEXT_LEN];
    out.copy_from_slice(&encrypted);
    Ok(EncryptedMlKemCiphertext::from_data(out))
}

fn decrypt_mlkem_ciphertext(
    crypto: &impl QlCrypto,
    symmetric: &mut SymmetricState,
    ciphertext: &EncryptedMlKemCiphertext,
) -> Result<MlKemCiphertext, WireError> {
    let plaintext = symmetric.decrypt_and_hash(crypto, ciphertext.as_bytes())?;
    if plaintext.len() != MlKemCiphertext::SIZE {
        return Err(WireError::InvalidPayload);
    }
    let mut out = [0u8; MlKemCiphertext::SIZE];
    out.copy_from_slice(&plaintext);
    Ok(MlKemCiphertext::from_data(out))
}

fn finalize_handshake(
    crypto: &impl QlCrypto,
    symmetric: SymmetricState,
    role: Role,
    remote_bundle: PeerBundle,
) -> FinalizedHandshake {
    let handshake_hash = symmetric.handshake_hash;
    let (tx_key, rx_key) = symmetric.split_for_role(crypto, role);
    let (initiator_rx, responder_rx) = derive_connection_ids(crypto, &handshake_hash);
    let (tx_connection_id, rx_connection_id) = match role {
        Role::Initiator => (responder_rx, initiator_rx),
        Role::Responder => (initiator_rx, responder_rx),
    };
    FinalizedHandshake {
        tx_key,
        rx_key,
        tx_connection_id,
        rx_connection_id,
        handshake_hash,
        remote_bundle,
    }
}

fn derive_connection_ids(
    crypto: &impl QlCrypto,
    handshake_hash: &[u8; 32],
) -> (ConnectionId, ConnectionId) {
    let initiator = crypto.sha256(&[CONNECTION_ID_DOMAIN, handshake_hash, b"initiator-rx"]);
    let responder = crypto.sha256(&[CONNECTION_ID_DOMAIN, handshake_hash, b"responder-rx"]);
    let mut initiator_rx = [0u8; ConnectionId::SIZE];
    let mut responder_rx = [0u8; ConnectionId::SIZE];
    initiator_rx.copy_from_slice(&initiator[..ConnectionId::SIZE]);
    responder_rx.copy_from_slice(&responder[..ConnectionId::SIZE]);
    (
        ConnectionId::from_data(initiator_rx),
        ConnectionId::from_data(responder_rx),
    )
}

fn hkdf2(
    crypto: &impl QlCrypto,
    chaining_key: &[u8; 32],
    input_key_material: &[u8],
) -> ([u8; 32], SessionKey) {
    let temp_key = hmac_sha256(crypto, chaining_key, &[input_key_material]);
    let out1 = hmac_sha256(crypto, &temp_key, &[&[1]]);
    let out2 = hmac_sha256(crypto, &temp_key, &[&out1, &[2]]);
    (out1, SessionKey::from_data(out2))
}

fn hkdf3(
    crypto: &impl QlCrypto,
    chaining_key: &[u8; 32],
    input_key_material: &[u8],
) -> ([u8; 32], [u8; 32], SessionKey) {
    let temp_key = hmac_sha256(crypto, chaining_key, &[input_key_material]);
    let out1 = hmac_sha256(crypto, &temp_key, &[&[1]]);
    let out2 = hmac_sha256(crypto, &temp_key, &[&out1, &[2]]);
    let out3 = hmac_sha256(crypto, &temp_key, &[&out2, &[3]]);
    (out1, out2, SessionKey::from_data(out3))
}

fn hmac_sha256(crypto: &impl QlCrypto, key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut key_block = [0u8; SHA256_BLOCK_LEN];
    if key.len() > SHA256_BLOCK_LEN {
        key_block[..32].copy_from_slice(&crypto.sha256(&[key]));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; SHA256_BLOCK_LEN];
    let mut opad = [0x5cu8; SHA256_BLOCK_LEN];
    for (dst, src) in ipad.iter_mut().zip(key_block.iter()) {
        *dst ^= *src;
    }
    for (dst, src) in opad.iter_mut().zip(key_block.iter()) {
        *dst ^= *src;
    }

    let mut inner_parts: Vec<&[u8]> = Vec::with_capacity(parts.len() + 1);
    inner_parts.push(&ipad);
    inner_parts.extend_from_slice(parts);
    let inner = crypto.sha256(&inner_parts);
    crypto.sha256(&[&opad, &inner])
}
