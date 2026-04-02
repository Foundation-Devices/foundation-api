use super::{
    decrypt_mlkem_ciphertext, encrypt_mlkem_ciphertext, finalize_handshake,
    generate_ephemeral_keypair, init_kk_symmetric, initialize_handshake_meta, mix_hash_ephemeral,
    mix_hash_routed_handshake, require_handshake_meta, EncryptedMlKemCiphertext, EphemeralKeyPair,
    EphemeralPublicKey, FinalizedHandshake, HandshakeHeader, Role, SymmetricState,
};
use crate::{
    codec, HandshakeKind, HandshakeMeta, MlKemCiphertext, PeerBundle, QlCrypto, QlIdentity,
    WireError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kk1 {
    pub header: HandshakeHeader,
    pub meta: HandshakeMeta,
    pub skem_ciphertext: MlKemCiphertext,
    pub ephemeral: EphemeralPublicKey,
}

impl Kk1 {
    pub const ENCODED_LEN: usize = HandshakeHeader::ENCODED_LEN
        + HandshakeMeta::ENCODED_LEN
        + MlKemCiphertext::SIZE
        + EphemeralPublicKey::ENCODED_LEN;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.header.encode_into(out);
        self.meta.encode_into(out);
        codec::push_bytes(out, self.skem_ciphertext.as_bytes());
        self.ephemeral.encode_into(out);
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let header = HandshakeHeader::decode_from(&mut reader)?;
        let meta = HandshakeMeta::decode_from(&mut reader)?;
        let skem_ciphertext = MlKemCiphertext::from_data(reader.take_array()?);
        let ephemeral =
            EphemeralPublicKey::decode(&reader.take_bytes(EphemeralPublicKey::ENCODED_LEN)?)?;
        reader.finish()?;
        Ok(Self {
            header,
            meta,
            skem_ciphertext,
            ephemeral,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kk2 {
    pub header: HandshakeHeader,
    pub meta: HandshakeMeta,
    pub ekem_ciphertext: MlKemCiphertext,
    pub skem_ciphertext: EncryptedMlKemCiphertext,
}

impl Kk2 {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KkStep {
    Send1,
    Recv1,
    Send2,
    Recv2,
    Done,
}

#[derive(Debug, Clone)]
pub struct KkHandshake {
    role: Role,
    step: KkStep,
    symmetric: SymmetricState,
    local: QlIdentity,
    remote_bundle: PeerBundle,
    local_ephemeral: Option<EphemeralKeyPair>,
    remote_ephemeral: Option<EphemeralPublicKey>,
    handshake_meta: Option<HandshakeMeta>,
}

impl KkHandshake {
    pub fn new_initiator(
        crypto: &impl QlCrypto,
        local: QlIdentity,
        remote_bundle: PeerBundle,
    ) -> Self {
        let symmetric = init_kk_symmetric(crypto, &local.bundle(), &remote_bundle);
        Self {
            role: Role::Initiator,
            step: KkStep::Send1,
            symmetric,
            local,
            remote_bundle,
            local_ephemeral: None,
            remote_ephemeral: None,
            handshake_meta: None,
        }
    }

    pub fn new_responder(
        crypto: &impl QlCrypto,
        local: QlIdentity,
        remote_bundle: PeerBundle,
    ) -> Self {
        let symmetric = init_kk_symmetric(crypto, &remote_bundle, &local.bundle());
        Self {
            role: Role::Responder,
            step: KkStep::Recv1,
            symmetric,
            local,
            remote_bundle,
            local_ephemeral: None,
            remote_ephemeral: None,
            handshake_meta: None,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.step == KkStep::Done
    }

    fn outbound_header(&self) -> HandshakeHeader {
        HandshakeHeader {
            sender: self.local.xid,
            recipient: self.remote_bundle.xid,
        }
    }

    fn inbound_header(&self) -> HandshakeHeader {
        HandshakeHeader {
            sender: self.remote_bundle.xid,
            recipient: self.local.xid,
        }
    }

    fn ensure_inbound_header(&self, header: HandshakeHeader) -> Result<(), WireError> {
        if header == self.inbound_header() {
            Ok(())
        } else {
            Err(WireError::InvalidPayload)
        }
    }

    pub fn write_1(
        &mut self,
        crypto: &impl QlCrypto,
        meta: HandshakeMeta,
    ) -> Result<Kk1, WireError> {
        if self.step != KkStep::Send1 {
            return Err(WireError::InvalidState);
        }
        initialize_handshake_meta(&mut self.handshake_meta, meta)?;
        let header = self.outbound_header();
        mix_hash_routed_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Kk1,
            &meta,
        );
        let (skem_ciphertext, skem_secret) =
            crypto.mlkem_encapsulate(&self.remote_bundle.mlkem_public_key);
        self.symmetric
            .encrypt_and_hash(crypto, skem_ciphertext.as_bytes())?;
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        let local_ephemeral = generate_ephemeral_keypair(crypto);
        let public = local_ephemeral.public();
        mix_hash_ephemeral(&mut self.symmetric, crypto, &public);

        self.local_ephemeral = Some(local_ephemeral);
        self.step = KkStep::Recv2;
        Ok(Kk1 {
            header,
            meta,
            skem_ciphertext,
            ephemeral: public,
        })
    }

    pub fn write_2(
        &mut self,
        crypto: &impl QlCrypto,
        meta: HandshakeMeta,
    ) -> Result<Kk2, WireError> {
        if self.step != KkStep::Send2 {
            return Err(WireError::InvalidState);
        }
        require_handshake_meta(&self.handshake_meta, meta)?;
        let header = self.outbound_header();
        mix_hash_routed_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Kk2,
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

        let (skem_ciphertext, skem_secret) =
            crypto.mlkem_encapsulate(&self.remote_bundle.mlkem_public_key);
        let skem_ciphertext =
            encrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &skem_ciphertext)?;
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        self.step = KkStep::Done;
        Ok(Kk2 {
            header,
            meta,
            ekem_ciphertext,
            skem_ciphertext,
        })
    }

    pub fn read_1(
        &mut self,
        crypto: &impl QlCrypto,
        now_seconds: u64,
        message: &Kk1,
    ) -> Result<(), WireError> {
        if self.step != KkStep::Recv1 {
            return Err(WireError::InvalidState);
        }
        message.meta.ensure_not_expired(now_seconds)?;
        initialize_handshake_meta(&mut self.handshake_meta, message.meta)?;
        self.ensure_inbound_header(message.header)?;
        mix_hash_routed_handshake(
            &mut self.symmetric,
            crypto,
            message.header,
            HandshakeKind::Kk1,
            &message.meta,
        );
        self.symmetric
            .decrypt_and_hash(crypto, message.skem_ciphertext.as_bytes())?;
        let skem_secret =
            crypto.mlkem_decapsulate(&self.local.mlkem_private_key, &message.skem_ciphertext);
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        mix_hash_ephemeral(&mut self.symmetric, crypto, &message.ephemeral);
        self.remote_ephemeral = Some(message.ephemeral.clone());
        self.step = KkStep::Send2;
        Ok(())
    }

    pub fn read_2(
        &mut self,
        crypto: &impl QlCrypto,
        now_seconds: u64,
        message: &Kk2,
    ) -> Result<(), WireError> {
        if self.step != KkStep::Recv2 {
            return Err(WireError::InvalidState);
        }
        message.meta.ensure_not_expired(now_seconds)?;
        require_handshake_meta(&self.handshake_meta, message.meta)?;
        self.ensure_inbound_header(message.header)?;
        mix_hash_routed_handshake(
            &mut self.symmetric,
            crypto,
            message.header,
            HandshakeKind::Kk2,
            &message.meta,
        );
        let local_ephemeral = self
            .local_ephemeral
            .as_ref()
            .ok_or(WireError::InvalidState)?;
        self.symmetric
            .mix_hash(crypto, message.ekem_ciphertext.as_bytes());
        let ekem_secret =
            crypto.mlkem_decapsulate(&local_ephemeral.mlkem.private, &message.ekem_ciphertext);
        self.symmetric.mix_key(crypto, ekem_secret.as_bytes());

        let skem_ciphertext =
            decrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &message.skem_ciphertext)?;
        let skem_secret = crypto.mlkem_decapsulate(&self.local.mlkem_private_key, &skem_ciphertext);
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        self.step = KkStep::Done;
        Ok(())
    }

    pub fn finalize(self, crypto: &impl QlCrypto) -> Result<FinalizedHandshake, WireError> {
        if !self.is_finished() {
            return Err(WireError::InvalidState);
        }
        Ok(finalize_handshake(
            crypto,
            self.symmetric,
            self.role,
            self.remote_bundle,
        ))
    }
}
