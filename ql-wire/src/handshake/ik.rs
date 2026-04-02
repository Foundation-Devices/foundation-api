use super::{
    decrypt_mlkem_ciphertext, decrypt_peer_bundle, encrypt_mlkem_ciphertext, encrypt_peer_bundle,
    finalize_handshake, generate_ephemeral_keypair, init_ik_symmetric, initialize_handshake_meta,
    mix_hash_ephemeral, mix_hash_routed_handshake, require_handshake_meta,
    EncryptedMlKemCiphertext, EncryptedPeerBundle, EphemeralKeyPair, EphemeralPublicKey,
    FinalizedHandshake, HandshakeHeader, Role, SymmetricState,
};
use crate::{
    codec, HandshakeKind, HandshakeMeta, MlKemCiphertext, PeerBundle, QlCrypto, QlIdentity,
    WireError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ik1 {
    pub header: HandshakeHeader,
    pub meta: HandshakeMeta,
    pub skem_ciphertext: MlKemCiphertext,
    pub ephemeral: EphemeralPublicKey,
    pub static_bundle: EncryptedPeerBundle,
}

impl Ik1 {
    pub const ENCODED_LEN: usize = HandshakeHeader::ENCODED_LEN
        + HandshakeMeta::ENCODED_LEN
        + MlKemCiphertext::SIZE
        + EphemeralPublicKey::ENCODED_LEN
        + EncryptedPeerBundle::ENCODED_LEN;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.header.encode_into(out);
        self.meta.encode_into(out);
        codec::push_bytes(out, self.skem_ciphertext.as_bytes());
        self.ephemeral.encode_into(out);
        codec::push_bytes(out, self.static_bundle.as_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let header = HandshakeHeader::decode_from(&mut reader)?;
        let meta = HandshakeMeta::decode_from(&mut reader)?;
        let skem_ciphertext = MlKemCiphertext::from_data(reader.take_array()?);
        let ephemeral =
            EphemeralPublicKey::decode(&reader.take_bytes(EphemeralPublicKey::ENCODED_LEN)?)?;
        let static_bundle = EncryptedPeerBundle::from_data(reader.take_array()?);
        reader.finish()?;
        Ok(Self {
            header,
            meta,
            skem_ciphertext,
            ephemeral,
            static_bundle,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ik2 {
    pub header: HandshakeHeader,
    pub meta: HandshakeMeta,
    pub ekem_ciphertext: MlKemCiphertext,
    pub skem_ciphertext: EncryptedMlKemCiphertext,
}

impl Ik2 {
    pub const ENCODED_LEN: usize = HandshakeHeader::ENCODED_LEN
        + HandshakeMeta::ENCODED_LEN
        + MlKemCiphertext::SIZE
        + EncryptedMlKemCiphertext::ENCODED_LEN;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.header.encode_into(out);
        self.meta.encode_into(out);
        codec::push_bytes(out, self.ekem_ciphertext.as_bytes());
        codec::push_bytes(out, self.skem_ciphertext.as_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let header = HandshakeHeader::decode_from(&mut reader)?;
        let meta = HandshakeMeta::decode_from(&mut reader)?;
        let ekem_ciphertext = MlKemCiphertext::from_data(reader.take_array()?);
        let skem_ciphertext = EncryptedMlKemCiphertext::from_data(reader.take_array()?);
        reader.finish()?;
        Ok(Self {
            header,
            meta,
            ekem_ciphertext,
            skem_ciphertext,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IkMessage {
    Message1(Ik1),
    Message2(Ik2),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IkStep {
    Send1,
    Recv1,
    Send2,
    Recv2,
    Done,
}

#[derive(Debug, Clone)]
pub struct IkHandshake {
    role: Role,
    step: IkStep,
    symmetric: SymmetricState,
    local: QlIdentity,
    remote_bundle: Option<PeerBundle>,
    local_ephemeral: Option<EphemeralKeyPair>,
    remote_ephemeral: Option<EphemeralPublicKey>,
    handshake_meta: Option<HandshakeMeta>,
}

impl IkHandshake {
    pub fn new_initiator(
        crypto: &impl QlCrypto,
        local: QlIdentity,
        remote_bundle: PeerBundle,
    ) -> Self {
        let symmetric = init_ik_symmetric(crypto, &remote_bundle);
        Self {
            role: Role::Initiator,
            step: IkStep::Send1,
            symmetric,
            local,
            remote_bundle: Some(remote_bundle),
            local_ephemeral: None,
            remote_ephemeral: None,
            handshake_meta: None,
        }
    }

    pub fn new_responder(
        crypto: &impl QlCrypto,
        local: QlIdentity,
        expected_remote: Option<PeerBundle>,
    ) -> Self {
        let symmetric = init_ik_symmetric(crypto, &local.bundle());
        Self {
            role: Role::Responder,
            step: IkStep::Recv1,
            symmetric,
            local,
            remote_bundle: expected_remote,
            local_ephemeral: None,
            remote_ephemeral: None,
            handshake_meta: None,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.step == IkStep::Done
    }

    fn outbound_header(&self) -> Result<HandshakeHeader, WireError> {
        let remote_bundle = self.remote_bundle.as_ref().ok_or(WireError::InvalidState)?;
        Ok(HandshakeHeader {
            sender: self.local.xid,
            recipient: remote_bundle.xid,
        })
    }

    fn ensure_inbound_recipient(&self, header: HandshakeHeader) -> Result<(), WireError> {
        if header.recipient == self.local.xid {
            Ok(())
        } else {
            Err(WireError::InvalidPayload)
        }
    }

    fn ensure_known_remote_sender(&self, header: HandshakeHeader) -> Result<(), WireError> {
        if let Some(remote_bundle) = self.remote_bundle.as_ref() {
            if header.sender != remote_bundle.xid {
                return Err(WireError::InvalidPayload);
            }
        }
        Ok(())
    }

    pub fn write_message(
        &mut self,
        crypto: &impl QlCrypto,
        meta: HandshakeMeta,
    ) -> Result<IkMessage, WireError> {
        match self.step {
            IkStep::Send1 => {
                initialize_handshake_meta(&mut self.handshake_meta, meta)?;
                let remote_bundle = self.remote_bundle.as_ref().ok_or(WireError::InvalidState)?;
                let header = self.outbound_header()?;
                mix_hash_routed_handshake(
                    &mut self.symmetric,
                    crypto,
                    header,
                    HandshakeKind::Ik1,
                    &meta,
                );
                let (skem_ciphertext, skem_secret) =
                    crypto.mlkem_encapsulate(&remote_bundle.mlkem_public_key);
                self.symmetric.mix_hash(crypto, skem_ciphertext.as_bytes());
                self.symmetric
                    .mix_key_and_hash(crypto, skem_secret.as_bytes());

                let local_ephemeral = generate_ephemeral_keypair(crypto);
                let public = local_ephemeral.public();
                mix_hash_ephemeral(&mut self.symmetric, crypto, &public);

                let static_bundle =
                    encrypt_peer_bundle(crypto, &mut self.symmetric, &self.local.bundle())?;

                self.local_ephemeral = Some(local_ephemeral);
                self.step = IkStep::Recv2;
                Ok(IkMessage::Message1(Ik1 {
                    header,
                    meta,
                    skem_ciphertext,
                    ephemeral: public,
                    static_bundle,
                }))
            }
            IkStep::Send2 => {
                require_handshake_meta(&self.handshake_meta, meta)?;
                let header = self.outbound_header()?;
                mix_hash_routed_handshake(
                    &mut self.symmetric,
                    crypto,
                    header,
                    HandshakeKind::Ik2,
                    &meta,
                );
                let remote_ephemeral = self
                    .remote_ephemeral
                    .clone()
                    .ok_or(WireError::InvalidState)?;
                let (ekem_ciphertext, ekem_secret) =
                    crypto.mlkem_encapsulate(&remote_ephemeral.mlkem_public_key);
                self.symmetric.mix_hash(crypto, ekem_ciphertext.as_bytes());
                self.symmetric.mix_key(crypto, ekem_secret.as_bytes());

                let remote_bundle = self.remote_bundle.as_ref().ok_or(WireError::InvalidState)?;
                let (skem_ciphertext, skem_secret) =
                    crypto.mlkem_encapsulate(&remote_bundle.mlkem_public_key);
                let skem_ciphertext =
                    encrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &skem_ciphertext)?;
                self.symmetric
                    .mix_key_and_hash(crypto, skem_secret.as_bytes());

                self.step = IkStep::Done;
                Ok(IkMessage::Message2(Ik2 {
                    header,
                    meta,
                    ekem_ciphertext,
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
        message: &IkMessage,
    ) -> Result<(), WireError> {
        match (&self.step, message) {
            (IkStep::Recv1, IkMessage::Message1(message)) => {
                message.meta.ensure_not_expired(now_seconds)?;
                initialize_handshake_meta(&mut self.handshake_meta, message.meta)?;
                self.ensure_inbound_recipient(message.header)?;
                self.ensure_known_remote_sender(message.header)?;
                mix_hash_routed_handshake(
                    &mut self.symmetric,
                    crypto,
                    message.header,
                    HandshakeKind::Ik1,
                    &message.meta,
                );
                self.symmetric
                    .mix_hash(crypto, message.skem_ciphertext.as_bytes());
                let skem_secret = crypto
                    .mlkem_decapsulate(&self.local.mlkem_private_key, &message.skem_ciphertext);
                self.symmetric
                    .mix_key_and_hash(crypto, skem_secret.as_bytes());

                mix_hash_ephemeral(&mut self.symmetric, crypto, &message.ephemeral);
                self.remote_ephemeral = Some(message.ephemeral.clone());

                let remote_bundle =
                    decrypt_peer_bundle(crypto, &mut self.symmetric, &message.static_bundle)?;
                if remote_bundle.xid != message.header.sender {
                    return Err(WireError::InvalidPayload);
                }
                match self.remote_bundle.as_ref() {
                    Some(expected) if expected != &remote_bundle => {
                        return Err(WireError::InvalidPayload);
                    }
                    Some(_) => {}
                    None => self.remote_bundle = Some(remote_bundle),
                }
                self.step = IkStep::Send2;
                Ok(())
            }
            (IkStep::Recv2, IkMessage::Message2(message)) => {
                message.meta.ensure_not_expired(now_seconds)?;
                require_handshake_meta(&self.handshake_meta, message.meta)?;
                self.ensure_inbound_recipient(message.header)?;
                self.ensure_known_remote_sender(message.header)?;
                mix_hash_routed_handshake(
                    &mut self.symmetric,
                    crypto,
                    message.header,
                    HandshakeKind::Ik2,
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

                let skem_ciphertext = decrypt_mlkem_ciphertext(
                    crypto,
                    &mut self.symmetric,
                    &message.skem_ciphertext,
                )?;
                let skem_secret =
                    crypto.mlkem_decapsulate(&self.local.mlkem_private_key, &skem_ciphertext);
                self.symmetric
                    .mix_key_and_hash(crypto, skem_secret.as_bytes());

                self.step = IkStep::Done;
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
