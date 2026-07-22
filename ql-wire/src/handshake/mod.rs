use ql_codec::{ByteSlice, Decode, Encode};

use crate::{
    Error, HandshakeKind, MlKemCiphertext, MlKemKeyPair, MlKemPublicKey, Nonce, PeerBundle,
    QlCrypto, RouteHeader, SessionKey, ENCRYPTED_MESSAGE_AUTH_SIZE,
};

mod challenge;
mod id;
mod ik;
mod pairing;
mod transport_params;
mod xx;

pub use challenge::{answer_peer_challenge, PeerChallenge, PendingChallengeConfirmation};
pub use id::HandshakeId;
pub use ik::{Ik1, Ik2, IkHandshake, IkPattern};
pub use pairing::{PairingId, PairingToken};
pub use transport_params::TransportParams;
pub use xx::{Xx1, Xx2, Xx3, Xx4, XxHandshake};

const SHA256_BLOCK_LEN: usize = 64;
const PROTOCOL_IK: &[u8] = b"ql-wire:pq-ik:v1";
const PROTOCOL_KK: &[u8] = b"ql-wire:pq-kk:v1";
const HANDSHAKE_PREAMBLE_DOMAIN: &[u8] = b"ql-wire:handshake-preamble:v1";

ql_codec::codec_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EphemeralPublicKey {
        pub mlkem_public_key: MlKemPublicKey,
    }
}

ql_codec::codec_newtype! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EncryptedMlKemCiphertext(pub Box<[u8; Self::SIZE]>);
}

impl EncryptedMlKemCiphertext {
    pub const SIZE: usize = MlKemCiphertext::SIZE + ENCRYPTED_MESSAGE_AUTH_SIZE;

    pub fn new(data: Box<[u8; Self::SIZE]>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        self.0.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPeerBundle(pub Box<[u8]>);

impl EncryptedPeerBundle {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Encode for EncryptedPeerBundle {
    fn encoded_len(&self) -> usize {
        self.0.len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        out.put_slice(self.as_bytes());
    }
}

impl<B: ByteSlice> ql_codec::Decode<B> for EncryptedPeerBundle {
    fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, ql_codec::Error> {
        let data = reader.take_all();
        Ok(Self(Box::from(&*data)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedHandshake {
    pub tx_key: SessionKey,
    pub rx_key: SessionKey,
    pub handshake_hash: [u8; 32],
    pub remote_bundle: PeerBundle,
    /// Transport parameters advertised by the remote peer
    pub remote_transport_params: TransportParams,
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
    ) -> Result<Vec<u8>, Error> {
        let key = self.key.as_ref().ok_or(Error::InvalidState)?;
        let nonce = Nonce::from_counter(self.nonce);
        let mut ciphertext = Vec::with_capacity(plaintext.len() + ENCRYPTED_MESSAGE_AUTH_SIZE);
        ciphertext.extend_from_slice(plaintext);
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
    ) -> Result<Vec<u8>, Error> {
        if ciphertext.len() < ENCRYPTED_MESSAGE_AUTH_SIZE {
            return Err(Error::InvalidPayload);
        }
        let split = ciphertext.len() - ENCRYPTED_MESSAGE_AUTH_SIZE;
        let (ciphertext, auth) = ciphertext.split_at(split);
        let mut plaintext = ciphertext.to_vec();
        let key = self.key.as_ref().ok_or(Error::InvalidState)?;
        let nonce = Nonce::from_counter(self.nonce);
        let mut auth_tag = [0u8; ENCRYPTED_MESSAGE_AUTH_SIZE];
        auth_tag.copy_from_slice(auth);
        if !crypto.aes256_gcm_decrypt(key, &nonce, aad, &mut plaintext, &auth_tag) {
            return Err(Error::DecryptFailed);
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

    fn mix_hash_ephemeral(&mut self, crypto: &impl QlCrypto, public: &EphemeralPublicKey) {
        self.mix_hash(crypto, public.mlkem_public_key.as_bytes());
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

    fn mix_psk_pairing_token(&mut self, crypto: &impl QlCrypto, pairing_token: PairingToken) {
        self.mix_key_and_hash(crypto, &pairing_token.psk(crypto));
    }

    fn encrypt_and_hash(
        &mut self,
        crypto: &impl QlCrypto,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
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
    ) -> Result<Vec<u8>, Error> {
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
        let k1 = SessionKey(hmac_sha256(crypto, &temp_key, &[&[1]]));
        let k2 = SessionKey(hmac_sha256(crypto, &temp_key, &[k1.as_bytes(), &[2]]));
        match role {
            Role::Initiator => (k1, k2),
            Role::Responder => (k2, k1),
        }
    }
}

fn generate_ephemeral_keypair(crypto: &impl QlCrypto) -> EphemeralKeyPair {
    EphemeralKeyPair {
        mlkem: crypto.mlkem_generate_keypair(),
    }
}

fn mix_hash_routed_handshake(
    symmetric: &mut SymmetricState,
    crypto: &impl QlCrypto,
    header: RouteHeader,
    kind: HandshakeKind,
    handshake_id: HandshakeId,
    transport_params: TransportParams,
) {
    mix_hash_handshake_preamble(
        symmetric,
        crypto,
        &header.encode_vec(),
        kind,
        handshake_id,
        transport_params,
    );
}

fn mix_hash_pairing_handshake(
    symmetric: &mut SymmetricState,
    crypto: &impl QlCrypto,
    header: RouteHeader,
    kind: HandshakeKind,
    handshake_id: HandshakeId,
    pairing_id: PairingId,
    transport_params: TransportParams,
) {
    let mut preamble = header.encode_vec();
    pairing_id.encode(&mut preamble);
    mix_hash_handshake_preamble(
        symmetric,
        crypto,
        &preamble,
        kind,
        handshake_id,
        transport_params,
    );
}

fn mix_hash_handshake_preamble(
    symmetric: &mut SymmetricState,
    crypto: &impl QlCrypto,
    header: &[u8],
    kind: HandshakeKind,
    handshake_id: HandshakeId,
    transport_params: TransportParams,
) {
    symmetric.mix_hash(crypto, HANDSHAKE_PREAMBLE_DOMAIN);
    symmetric.mix_hash(crypto, header);
    symmetric.mix_hash(crypto, &[kind as u8]);
    symmetric.mix_hash(crypto, &handshake_id.encode_vec());
    symmetric.mix_hash(crypto, &transport_params.encode_vec());
}

fn initialize_handshake_id(
    expected: &mut Option<HandshakeId>,
    handshake_id: HandshakeId,
) -> Result<(), Error> {
    match expected {
        Some(stored) if *stored != handshake_id => Err(Error::InvalidHandshakeId),
        Some(_) => Ok(()),
        None => {
            *expected = Some(handshake_id);
            Ok(())
        }
    }
}

fn require_handshake_id(
    expected: Option<&HandshakeId>,
    handshake_id: HandshakeId,
) -> Result<(), Error> {
    match expected {
        Some(stored) if *stored == handshake_id => Ok(()),
        _ => Err(Error::InvalidHandshakeId),
    }
}

fn encrypt_peer_bundle(
    crypto: &impl QlCrypto,
    symmetric: &mut SymmetricState,
    bundle: &PeerBundle,
) -> Result<EncryptedPeerBundle, Error> {
    let ciphertext = symmetric.encrypt_and_hash(crypto, &bundle.encode_vec())?;
    Ok(EncryptedPeerBundle(ciphertext.into_boxed_slice()))
}

fn decrypt_peer_bundle(
    crypto: &impl QlCrypto,
    symmetric: &mut SymmetricState,
    bundle: &EncryptedPeerBundle,
) -> Result<PeerBundle, Error> {
    let plaintext = symmetric.decrypt_and_hash(crypto, bundle.as_bytes())?;
    let bundle = PeerBundle::decode_bytes(plaintext.as_slice())?;
    bundle.validate(crypto)?;
    Ok(bundle)
}

fn encrypt_mlkem_ciphertext(
    crypto: &impl QlCrypto,
    symmetric: &mut SymmetricState,
    ciphertext: &MlKemCiphertext,
) -> Result<EncryptedMlKemCiphertext, Error> {
    let encrypted = symmetric.encrypt_and_hash(crypto, ciphertext.as_bytes())?;
    let out: Box<[u8; EncryptedMlKemCiphertext::SIZE]> =
        encrypted.try_into().map_err(|_| Error::InvalidState)?;
    Ok(EncryptedMlKemCiphertext::new(out))
}

fn decrypt_mlkem_ciphertext(
    crypto: &impl QlCrypto,
    symmetric: &mut SymmetricState,
    ciphertext: &EncryptedMlKemCiphertext,
) -> Result<MlKemCiphertext, Error> {
    let plaintext = symmetric.decrypt_and_hash(crypto, ciphertext.as_bytes())?;
    let out: Box<[u8; MlKemCiphertext::SIZE]> =
        plaintext.try_into().map_err(|_| Error::InvalidPayload)?;
    Ok(MlKemCiphertext::new(out))
}

fn finalize_handshake(
    crypto: &impl QlCrypto,
    symmetric: &SymmetricState,
    role: Role,
    remote_bundle: PeerBundle,
    remote_transport_params: TransportParams,
) -> FinalizedHandshake {
    let handshake_hash = symmetric.handshake_hash;
    let (tx_key, rx_key) = symmetric.split_for_role(crypto, role);
    FinalizedHandshake {
        tx_key,
        rx_key,
        handshake_hash,
        remote_bundle,
        remote_transport_params,
    }
}

fn hkdf2(
    crypto: &impl QlCrypto,
    chaining_key: &[u8; 32],
    input_key_material: &[u8],
) -> ([u8; 32], SessionKey) {
    let temp_key = hmac_sha256(crypto, chaining_key, &[input_key_material]);
    let out1 = hmac_sha256(crypto, &temp_key, &[&[1]]);
    let out2 = hmac_sha256(crypto, &temp_key, &[&out1, &[2]]);
    (out1, SessionKey(out2))
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
    (out1, out2, SessionKey(out3))
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
