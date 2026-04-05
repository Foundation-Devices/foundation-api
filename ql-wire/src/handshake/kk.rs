use super::{
    decrypt_mlkem_ciphertext, encrypt_mlkem_ciphertext, finalize_handshake,
    generate_ephemeral_keypair, init_kk_symmetric, initialize_handshake_meta, mix_hash_ephemeral,
    mix_hash_routed_handshake, require_handshake_meta, EncryptedMlKemCiphertext, EphemeralKeyPair,
    EphemeralPublicKey, FinalizedHandshake, HandshakeHeader, Role, SymmetricState, TransportParams,
};
use crate::{
    codec, ByteSlice, HandshakeKind, HandshakeMeta, MlKemCiphertext, PeerBundle, QlCrypto,
    QlIdentity, WireError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kk1 {
    pub header: HandshakeHeader,
    pub meta: HandshakeMeta,
    pub transport_params: TransportParams,
    pub skem_ciphertext: MlKemCiphertext,
    pub ephemeral: EphemeralPublicKey,
}

impl Kk1 {
    pub const WIRE_SIZE: usize = HandshakeHeader::WIRE_SIZE
        + HandshakeMeta::WIRE_SIZE
        + TransportParams::WIRE_SIZE
        + MlKemCiphertext::SIZE
        + EphemeralPublicKey::WIRE_SIZE;

    pub fn encode_into<'a>(&self, out: &'a mut [u8]) -> &'a mut [u8] {
        let out = self.header.encode_into(out);
        let out = self.meta.encode_into(out);
        let out = self.transport_params.encode_into(out);
        let out = codec::write_bytes(out, self.skem_ciphertext.as_bytes());
        self.ephemeral.encode_into(out)
    }
}

impl<B: ByteSlice> codec::WireParse<B> for Kk1 {
    fn parse(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            header: reader.parse()?,
            meta: reader.parse()?,
            transport_params: reader.parse()?,
            skem_ciphertext: MlKemCiphertext::new(reader.take_boxed_array()?),
            ephemeral: reader.parse()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kk2 {
    pub header: HandshakeHeader,
    pub meta: HandshakeMeta,
    pub transport_params: TransportParams,
    pub ekem_ciphertext: MlKemCiphertext,
    pub skem_ciphertext: EncryptedMlKemCiphertext,
}

impl Kk2 {
    pub const WIRE_SIZE: usize = HandshakeHeader::WIRE_SIZE
        + HandshakeMeta::WIRE_SIZE
        + TransportParams::WIRE_SIZE
        + MlKemCiphertext::SIZE
        + EncryptedMlKemCiphertext::WIRE_SIZE;

    pub fn encode_into<'a>(&self, out: &'a mut [u8]) -> &'a mut [u8] {
        let out = self.header.encode_into(out);
        let out = self.meta.encode_into(out);
        let out = self.transport_params.encode_into(out);
        let out = codec::write_bytes(out, self.ekem_ciphertext.as_bytes());
        codec::write_bytes(out, self.skem_ciphertext.as_bytes())
    }
}

impl<B: ByteSlice> codec::WireParse<B> for Kk2 {
    fn parse(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            header: reader.parse()?,
            meta: reader.parse()?,
            transport_params: reader.parse()?,
            ekem_ciphertext: MlKemCiphertext::new(reader.take_boxed_array()?),
            skem_ciphertext: EncryptedMlKemCiphertext::new(reader.take_boxed_array()?),
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
    local_transport_params: TransportParams,
    remote_transport_params: Option<TransportParams>,
}

impl KkHandshake {
    pub fn new_initiator(
        crypto: &impl QlCrypto,
        local: QlIdentity,
        remote_bundle: PeerBundle,
        local_transport_params: TransportParams,
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
            local_transport_params,
            remote_transport_params: None,
        }
    }

    pub fn new_responder(
        crypto: &impl QlCrypto,
        local: QlIdentity,
        remote_bundle: PeerBundle,
        local_transport_params: TransportParams,
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
            local_transport_params,
            remote_transport_params: None,
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
            self.local_transport_params,
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
            transport_params: self.local_transport_params,
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
        require_handshake_meta(self.handshake_meta.as_ref(), meta)?;
        let header = self.outbound_header();
        mix_hash_routed_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Kk2,
            &meta,
            self.local_transport_params,
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
            transport_params: self.local_transport_params,
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
            message.transport_params,
        );
        self.symmetric
            .decrypt_and_hash(crypto, message.skem_ciphertext.as_bytes())?;
        let skem_secret =
            crypto.mlkem_decapsulate(&self.local.mlkem_private_key, &message.skem_ciphertext);
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        mix_hash_ephemeral(&mut self.symmetric, crypto, &message.ephemeral);
        self.remote_ephemeral = Some(message.ephemeral.clone());
        self.remote_transport_params = Some(message.transport_params);
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
        require_handshake_meta(self.handshake_meta.as_ref(), message.meta)?;
        self.ensure_inbound_header(message.header)?;
        mix_hash_routed_handshake(
            &mut self.symmetric,
            crypto,
            message.header,
            HandshakeKind::Kk2,
            &message.meta,
            message.transport_params,
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

        self.remote_transport_params = Some(message.transport_params);
        self.step = KkStep::Done;
        Ok(())
    }

    pub fn finalize(self, crypto: &impl QlCrypto) -> Result<FinalizedHandshake, WireError> {
        if !self.is_finished() {
            return Err(WireError::InvalidState);
        }
        let remote_transport_params = self
            .remote_transport_params
            .ok_or(WireError::InvalidState)?;
        Ok(finalize_handshake(
            crypto,
            &self.symmetric,
            self.role,
            self.remote_bundle,
            remote_transport_params,
        ))
    }
}
