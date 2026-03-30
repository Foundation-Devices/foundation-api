use super::{
    decrypt_mlkem_ciphertext, decrypt_peer_bundle, encrypt_mlkem_ciphertext, encrypt_peer_bundle,
    finalize_handshake, generate_ephemeral_keypair, initialize_handshake_meta, mix_hash_ephemeral,
    mix_hash_xx_handshake, require_handshake_meta, EncryptedMlKemCiphertext, EncryptedPeerBundle,
    EphemeralKeyPair, EphemeralPublicKey, FinalizedHandshake, Role, SymmetricState, PROTOCOL_XX,
};
use crate::{
    codec, HandshakeKind, HandshakeMeta, MlKemCiphertext, PeerBundle, QlCrypto, QlIdentity,
    WireError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xx1 {
    pub meta: HandshakeMeta,
    pub ephemeral: EphemeralPublicKey,
}

impl Xx1 {
    pub const ENCODED_LEN: usize = HandshakeMeta::ENCODED_LEN + EphemeralPublicKey::ENCODED_LEN;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.meta.encode_into(out);
        self.ephemeral.encode_into(out);
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let meta = HandshakeMeta::decode_from(&mut reader)?;
        let ephemeral =
            EphemeralPublicKey::decode(&reader.take_bytes(EphemeralPublicKey::ENCODED_LEN)?)?;
        reader.finish()?;
        Ok(Self { meta, ephemeral })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xx2 {
    pub meta: HandshakeMeta,
    pub ekem_ciphertext: MlKemCiphertext,
    pub static_bundle: EncryptedPeerBundle,
}

impl Xx2 {
    pub const ENCODED_LEN: usize =
        HandshakeMeta::ENCODED_LEN + MlKemCiphertext::SIZE + EncryptedPeerBundle::ENCODED_LEN;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.meta.encode_into(out);
        codec::push_bytes(out, self.ekem_ciphertext.as_bytes());
        codec::push_bytes(out, self.static_bundle.as_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let meta = HandshakeMeta::decode_from(&mut reader)?;
        let ekem_ciphertext = MlKemCiphertext::from_data(reader.take_array()?);
        let static_bundle = EncryptedPeerBundle::from_data(reader.take_array()?);
        reader.finish()?;
        Ok(Self {
            meta,
            ekem_ciphertext,
            static_bundle,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xx3 {
    pub meta: HandshakeMeta,
    pub skem_ciphertext: EncryptedMlKemCiphertext,
    pub static_bundle: EncryptedPeerBundle,
}

impl Xx3 {
    pub const ENCODED_LEN: usize = HandshakeMeta::ENCODED_LEN
        + EncryptedMlKemCiphertext::ENCODED_LEN
        + EncryptedPeerBundle::ENCODED_LEN;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.meta.encode_into(out);
        codec::push_bytes(out, self.skem_ciphertext.as_bytes());
        codec::push_bytes(out, self.static_bundle.as_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let meta = HandshakeMeta::decode_from(&mut reader)?;
        let skem_ciphertext = EncryptedMlKemCiphertext::from_data(reader.take_array()?);
        let static_bundle = EncryptedPeerBundle::from_data(reader.take_array()?);
        reader.finish()?;
        Ok(Self {
            meta,
            skem_ciphertext,
            static_bundle,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xx4 {
    pub meta: HandshakeMeta,
    pub skem_ciphertext: EncryptedMlKemCiphertext,
}

impl Xx4 {
    pub const ENCODED_LEN: usize =
        HandshakeMeta::ENCODED_LEN + EncryptedMlKemCiphertext::ENCODED_LEN;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.meta.encode_into(out);
        codec::push_bytes(out, self.skem_ciphertext.as_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let meta = HandshakeMeta::decode_from(&mut reader)?;
        let skem_ciphertext = EncryptedMlKemCiphertext::from_data(reader.take_array()?);
        reader.finish()?;
        Ok(Self {
            meta,
            skem_ciphertext,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XxMessage {
    Message1(Xx1),
    Message2(Xx2),
    Message3(Xx3),
    Message4(Xx4),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XxStep {
    Send1,
    Recv1,
    Send2,
    Recv2,
    Send3,
    Recv3,
    Send4,
    Recv4,
    Done,
}

#[derive(Debug, Clone)]
pub struct XxHandshake {
    role: Role,
    step: XxStep,
    symmetric: SymmetricState,
    local: QlIdentity,
    local_ephemeral: Option<EphemeralKeyPair>,
    remote_ephemeral: Option<EphemeralPublicKey>,
    remote_bundle: Option<PeerBundle>,
    handshake_meta: Option<HandshakeMeta>,
}

impl XxHandshake {
    pub fn new_initiator(crypto: &impl QlCrypto, local: QlIdentity) -> Self {
        Self {
            role: Role::Initiator,
            step: XxStep::Send1,
            symmetric: SymmetricState::new(crypto, PROTOCOL_XX),
            local,
            local_ephemeral: None,
            remote_ephemeral: None,
            remote_bundle: None,
            handshake_meta: None,
        }
    }

    pub fn new_responder(crypto: &impl QlCrypto, local: QlIdentity) -> Self {
        Self {
            role: Role::Responder,
            step: XxStep::Recv1,
            symmetric: SymmetricState::new(crypto, PROTOCOL_XX),
            local,
            local_ephemeral: None,
            remote_ephemeral: None,
            remote_bundle: None,
            handshake_meta: None,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.step == XxStep::Done
    }

    pub fn write_message(
        &mut self,
        crypto: &impl QlCrypto,
        meta: HandshakeMeta,
    ) -> Result<XxMessage, WireError> {
        match self.step {
            XxStep::Send1 => {
                initialize_handshake_meta(&mut self.handshake_meta, meta)?;
                mix_hash_xx_handshake(&mut self.symmetric, crypto, HandshakeKind::Xx1, &meta);
                let local_ephemeral = generate_ephemeral_keypair(crypto);
                let public = local_ephemeral.public();
                mix_hash_ephemeral(&mut self.symmetric, crypto, &public);
                self.local_ephemeral = Some(local_ephemeral);
                self.step = XxStep::Recv2;
                Ok(XxMessage::Message1(Xx1 {
                    meta,
                    ephemeral: public,
                }))
            }
            XxStep::Send2 => {
                require_handshake_meta(&self.handshake_meta, meta)?;
                mix_hash_xx_handshake(&mut self.symmetric, crypto, HandshakeKind::Xx2, &meta);
                let remote_ephemeral = self
                    .remote_ephemeral
                    .clone()
                    .ok_or(WireError::InvalidState)?;
                let (ekem_ciphertext, ekem_secret) =
                    crypto.mlkem_encapsulate(&remote_ephemeral.mlkem_public_key);
                self.symmetric.mix_hash(crypto, ekem_ciphertext.as_bytes());
                self.symmetric.mix_key(crypto, ekem_secret.as_bytes());

                let static_bundle =
                    encrypt_peer_bundle(crypto, &mut self.symmetric, &self.local.bundle())?;

                self.step = XxStep::Recv3;
                Ok(XxMessage::Message2(Xx2 {
                    meta,
                    ekem_ciphertext,
                    static_bundle,
                }))
            }
            XxStep::Send3 => {
                require_handshake_meta(&self.handshake_meta, meta)?;
                mix_hash_xx_handshake(&mut self.symmetric, crypto, HandshakeKind::Xx3, &meta);
                let remote_bundle = self.remote_bundle.clone().ok_or(WireError::InvalidState)?;
                let (skem_ciphertext, skem_secret) =
                    crypto.mlkem_encapsulate(&remote_bundle.mlkem_public_key);
                let skem_ciphertext =
                    encrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &skem_ciphertext)?;
                self.symmetric
                    .mix_key_and_hash(crypto, skem_secret.as_bytes());

                let static_bundle =
                    encrypt_peer_bundle(crypto, &mut self.symmetric, &self.local.bundle())?;

                self.step = XxStep::Recv4;
                Ok(XxMessage::Message3(Xx3 {
                    meta,
                    skem_ciphertext,
                    static_bundle,
                }))
            }
            XxStep::Send4 => {
                require_handshake_meta(&self.handshake_meta, meta)?;
                mix_hash_xx_handshake(&mut self.symmetric, crypto, HandshakeKind::Xx4, &meta);
                let remote_bundle = self.remote_bundle.clone().ok_or(WireError::InvalidState)?;
                let (skem_ciphertext, skem_secret) =
                    crypto.mlkem_encapsulate(&remote_bundle.mlkem_public_key);
                let skem_ciphertext =
                    encrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &skem_ciphertext)?;
                self.symmetric
                    .mix_key_and_hash(crypto, skem_secret.as_bytes());
                self.step = XxStep::Done;

                Ok(XxMessage::Message4(Xx4 {
                    meta,
                    skem_ciphertext,
                }))
            }
            _ => Err(WireError::InvalidState),
        }
    }

    pub fn read_message(
        &mut self,
        crypto: &impl QlCrypto,
        now_seconds: u64,
        message: &XxMessage,
    ) -> Result<(), WireError> {
        match (&self.step, message) {
            (XxStep::Recv1, XxMessage::Message1(message)) => {
                message.meta.ensure_not_expired(now_seconds)?;
                initialize_handshake_meta(&mut self.handshake_meta, message.meta)?;
                mix_hash_xx_handshake(
                    &mut self.symmetric,
                    crypto,
                    HandshakeKind::Xx1,
                    &message.meta,
                );
                mix_hash_ephemeral(&mut self.symmetric, crypto, &message.ephemeral);
                self.remote_ephemeral = Some(message.ephemeral.clone());
                self.step = XxStep::Send2;
                Ok(())
            }
            (XxStep::Recv2, XxMessage::Message2(message)) => {
                message.meta.ensure_not_expired(now_seconds)?;
                require_handshake_meta(&self.handshake_meta, message.meta)?;
                mix_hash_xx_handshake(
                    &mut self.symmetric,
                    crypto,
                    HandshakeKind::Xx2,
                    &message.meta,
                );
                let local_ephemeral = self
                    .local_ephemeral
                    .as_ref()
                    .ok_or(WireError::InvalidState)?;
                self.symmetric
                    .mix_hash(crypto, message.ekem_ciphertext.as_bytes());
                let ekem_secret = crypto
                    .mlkem_decapsulate(&local_ephemeral.mlkem.private, &message.ekem_ciphertext);
                self.symmetric.mix_key(crypto, ekem_secret.as_bytes());

                let remote_bundle =
                    decrypt_peer_bundle(crypto, &mut self.symmetric, &message.static_bundle)?;
                self.remote_bundle = Some(remote_bundle);
                self.step = XxStep::Send3;
                Ok(())
            }
            (XxStep::Recv3, XxMessage::Message3(message)) => {
                message.meta.ensure_not_expired(now_seconds)?;
                require_handshake_meta(&self.handshake_meta, message.meta)?;
                mix_hash_xx_handshake(
                    &mut self.symmetric,
                    crypto,
                    HandshakeKind::Xx3,
                    &message.meta,
                );
                let skem_ciphertext = decrypt_mlkem_ciphertext(
                    crypto,
                    &mut self.symmetric,
                    &message.skem_ciphertext,
                )?;
                let skem_secret =
                    crypto.mlkem_decapsulate(&self.local.mlkem_private_key, &skem_ciphertext);
                self.symmetric
                    .mix_key_and_hash(crypto, skem_secret.as_bytes());

                let remote_bundle =
                    decrypt_peer_bundle(crypto, &mut self.symmetric, &message.static_bundle)?;
                self.remote_bundle = Some(remote_bundle);
                self.step = XxStep::Send4;
                Ok(())
            }
            (XxStep::Recv4, XxMessage::Message4(message)) => {
                message.meta.ensure_not_expired(now_seconds)?;
                require_handshake_meta(&self.handshake_meta, message.meta)?;
                mix_hash_xx_handshake(
                    &mut self.symmetric,
                    crypto,
                    HandshakeKind::Xx4,
                    &message.meta,
                );
                let skem_ciphertext = decrypt_mlkem_ciphertext(
                    crypto,
                    &mut self.symmetric,
                    &message.skem_ciphertext,
                )?;
                let skem_secret =
                    crypto.mlkem_decapsulate(&self.local.mlkem_private_key, &skem_ciphertext);
                self.symmetric
                    .mix_key_and_hash(crypto, skem_secret.as_bytes());
                self.step = XxStep::Done;
                Ok(())
            }
            _ => Err(WireError::InvalidState),
        }
    }

    pub fn finalize(self, crypto: &impl QlCrypto) -> Result<FinalizedHandshake, WireError> {
        if !self.is_finished() {
            return Err(WireError::InvalidState);
        }
        let remote_bundle = self.remote_bundle.ok_or(WireError::InvalidState)?;
        Ok(finalize_handshake(
            crypto,
            self.symmetric,
            self.role,
            remote_bundle,
        ))
    }
}
