use super::{
    decrypt_mlkem_ciphertext, decrypt_peer_bundle, encrypt_mlkem_ciphertext, encrypt_peer_bundle,
    finalize_handshake, generate_ephemeral_keypair, init_xx_symmetric, initialize_handshake_meta,
    initialize_transport_params, mix_hash_ephemeral, mix_hash_pairing_handshake,
    require_handshake_meta, require_transport_params, EncryptedMlKemCiphertext,
    EncryptedPeerBundle, EphemeralKeyPair, EphemeralPublicKey, FinalizedHandshake, Role,
    SymmetricState, TransportParams, XxHeader,
};
use crate::{
    codec, ByteSlice, HandshakeKind, HandshakeMeta, MlKemCiphertext, PairingToken, PeerBundle,
    QlCrypto, QlIdentity, WireEncode, WireError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xx1 {
    pub header: XxHeader,
    pub meta: HandshakeMeta,
    pub transport_params: TransportParams,
    pub ephemeral: EphemeralPublicKey,
}

impl Xx1 {
    pub const WIRE_SIZE: usize = XxHeader::WIRE_SIZE
        + HandshakeMeta::WIRE_SIZE
        + TransportParams::WIRE_SIZE
        + EphemeralPublicKey::WIRE_SIZE;
}

impl<B: ByteSlice> codec::WireDecode<B> for Xx1 {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            header: reader.decode()?,
            meta: reader.decode()?,
            transport_params: reader.decode()?,
            ephemeral: reader.decode()?,
        })
    }
}

impl WireEncode for Xx1 {
    fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.header.encode(out);
        self.meta.encode(out);
        self.transport_params.encode(out);
        self.ephemeral.encode(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xx2 {
    pub header: XxHeader,
    pub meta: HandshakeMeta,
    pub transport_params: TransportParams,
    pub ekem_ciphertext: MlKemCiphertext,
    pub static_bundle: EncryptedPeerBundle,
}

impl Xx2 {
    pub const WIRE_SIZE: usize = XxHeader::WIRE_SIZE
        + HandshakeMeta::WIRE_SIZE
        + TransportParams::WIRE_SIZE
        + MlKemCiphertext::SIZE
        + EncryptedPeerBundle::WIRE_SIZE;
}

impl<B: ByteSlice> codec::WireDecode<B> for Xx2 {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            header: reader.decode()?,
            meta: reader.decode()?,
            transport_params: reader.decode()?,
            ekem_ciphertext: reader.decode()?,
            static_bundle: reader.decode()?,
        })
    }
}

impl WireEncode for Xx2 {
    fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.header.encode(out);
        self.meta.encode(out);
        self.transport_params.encode(out);
        self.ekem_ciphertext.encode(out);
        self.static_bundle.encode(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xx3 {
    pub header: XxHeader,
    pub meta: HandshakeMeta,
    pub transport_params: TransportParams,
    pub skem_ciphertext: EncryptedMlKemCiphertext,
    pub static_bundle: EncryptedPeerBundle,
}

impl Xx3 {
    pub const WIRE_SIZE: usize = XxHeader::WIRE_SIZE
        + HandshakeMeta::WIRE_SIZE
        + TransportParams::WIRE_SIZE
        + EncryptedMlKemCiphertext::WIRE_SIZE
        + EncryptedPeerBundle::WIRE_SIZE;
}

impl<B: ByteSlice> codec::WireDecode<B> for Xx3 {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            header: reader.decode()?,
            meta: reader.decode()?,
            transport_params: reader.decode()?,
            skem_ciphertext: reader.decode()?,
            static_bundle: reader.decode()?,
        })
    }
}

impl WireEncode for Xx3 {
    fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.header.encode(out);
        self.meta.encode(out);
        self.transport_params.encode(out);
        self.skem_ciphertext.encode(out);
        self.static_bundle.encode(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xx4 {
    pub header: XxHeader,
    pub meta: HandshakeMeta,
    pub transport_params: TransportParams,
    pub skem_ciphertext: EncryptedMlKemCiphertext,
}

impl Xx4 {
    pub const WIRE_SIZE: usize = XxHeader::WIRE_SIZE
        + HandshakeMeta::WIRE_SIZE
        + TransportParams::WIRE_SIZE
        + EncryptedMlKemCiphertext::WIRE_SIZE;
}

impl<B: ByteSlice> codec::WireDecode<B> for Xx4 {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            header: reader.decode()?,
            meta: reader.decode()?,
            transport_params: reader.decode()?,
            skem_ciphertext: reader.decode()?,
        })
    }
}

impl WireEncode for Xx4 {
    fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.header.encode(out);
        self.meta.encode(out);
        self.transport_params.encode(out);
        self.skem_ciphertext.encode(out);
    }
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
    pairing_token: PairingToken,
    remote_bundle: Option<PeerBundle>,
    local_ephemeral: Option<EphemeralKeyPair>,
    remote_ephemeral: Option<EphemeralPublicKey>,
    handshake_meta: Option<HandshakeMeta>,
    local_transport_params: TransportParams,
    remote_transport_params: Option<TransportParams>,
}

impl XxHandshake {
    pub fn new_initiator(
        crypto: &impl QlCrypto,
        local: QlIdentity,
        pairing_token: PairingToken,
        local_transport_params: TransportParams,
    ) -> Self {
        Self {
            role: Role::Initiator,
            step: XxStep::Send1,
            symmetric: init_xx_symmetric(crypto),
            local,
            pairing_token,
            remote_bundle: None,
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
        pairing_token: PairingToken,
        local_transport_params: TransportParams,
    ) -> Self {
        Self {
            role: Role::Responder,
            step: XxStep::Recv1,
            symmetric: init_xx_symmetric(crypto),
            local,
            pairing_token,
            remote_bundle: None,
            local_ephemeral: None,
            remote_ephemeral: None,
            handshake_meta: None,
            local_transport_params,
            remote_transport_params: None,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.step == XxStep::Done
    }

    pub fn pairing_token(&self) -> PairingToken {
        self.pairing_token
    }

    pub fn remote_bundle(&self) -> Option<&PeerBundle> {
        self.remote_bundle.as_ref()
    }

    fn header(&self) -> XxHeader {
        XxHeader {
            pairing_token: self.pairing_token,
        }
    }

    fn ensure_inbound_header(&self, header: XxHeader) -> Result<(), WireError> {
        if header == self.header() {
            Ok(())
        } else {
            Err(WireError::InvalidPayload)
        }
    }

    pub fn write_1(
        &mut self,
        crypto: &impl QlCrypto,
        meta: HandshakeMeta,
    ) -> Result<Xx1, WireError> {
        if self.step != XxStep::Send1 {
            return Err(WireError::InvalidState);
        }
        initialize_handshake_meta(&mut self.handshake_meta, meta)?;
        let header = self.header();
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Xx1,
            &meta,
            self.local_transport_params,
        );

        let local_ephemeral = generate_ephemeral_keypair(crypto);
        let ephemeral = local_ephemeral.public();
        mix_hash_ephemeral(&mut self.symmetric, crypto, &ephemeral);

        self.local_ephemeral = Some(local_ephemeral);
        self.step = XxStep::Recv2;
        Ok(Xx1 {
            header,
            meta,
            transport_params: self.local_transport_params,
            ephemeral,
        })
    }

    pub fn read_1(
        &mut self,
        crypto: &impl QlCrypto,
        now_seconds: u64,
        message: &Xx1,
    ) -> Result<(), WireError> {
        if self.step != XxStep::Recv1 {
            return Err(WireError::InvalidState);
        }
        message.meta.ensure_not_expired(now_seconds)?;
        initialize_handshake_meta(&mut self.handshake_meta, message.meta)?;
        self.ensure_inbound_header(message.header)?;
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            message.header,
            HandshakeKind::Xx1,
            &message.meta,
            message.transport_params,
        );
        mix_hash_ephemeral(&mut self.symmetric, crypto, &message.ephemeral);

        self.remote_ephemeral = Some(message.ephemeral.clone());
        initialize_transport_params(&mut self.remote_transport_params, message.transport_params)?;
        self.step = XxStep::Send2;
        Ok(())
    }

    pub fn write_2(
        &mut self,
        crypto: &impl QlCrypto,
        meta: HandshakeMeta,
    ) -> Result<Xx2, WireError> {
        if self.step != XxStep::Send2 {
            return Err(WireError::InvalidState);
        }
        require_handshake_meta(self.handshake_meta.as_ref(), meta)?;
        let header = self.header();
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Xx2,
            &meta,
            self.local_transport_params,
        );

        let remote_ephemeral = self
            .remote_ephemeral
            .as_ref()
            .ok_or(WireError::InvalidState)?;
        let (ekem_ciphertext, ekem_secret) =
            crypto.mlkem_encapsulate(&remote_ephemeral.mlkem_public_key);
        self.symmetric.mix_hash(crypto, ekem_ciphertext.as_bytes());
        self.symmetric.mix_key(crypto, ekem_secret.as_bytes());

        let static_bundle = encrypt_peer_bundle(crypto, &mut self.symmetric, &self.local.bundle())?;

        self.step = XxStep::Recv3;
        Ok(Xx2 {
            header,
            meta,
            transport_params: self.local_transport_params,
            ekem_ciphertext,
            static_bundle,
        })
    }

    pub fn read_2(
        &mut self,
        crypto: &impl QlCrypto,
        now_seconds: u64,
        message: &Xx2,
    ) -> Result<(), WireError> {
        if self.step != XxStep::Recv2 {
            return Err(WireError::InvalidState);
        }
        message.meta.ensure_not_expired(now_seconds)?;
        require_handshake_meta(self.handshake_meta.as_ref(), message.meta)?;
        self.ensure_inbound_header(message.header)?;
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            message.header,
            HandshakeKind::Xx2,
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

        let remote_bundle =
            decrypt_peer_bundle(crypto, &mut self.symmetric, &message.static_bundle)?;
        self.remote_bundle = Some(remote_bundle);
        initialize_transport_params(&mut self.remote_transport_params, message.transport_params)?;
        self.step = XxStep::Send3;
        Ok(())
    }

    pub fn write_3(
        &mut self,
        crypto: &impl QlCrypto,
        meta: HandshakeMeta,
    ) -> Result<Xx3, WireError> {
        if self.step != XxStep::Send3 {
            return Err(WireError::InvalidState);
        }
        require_handshake_meta(self.handshake_meta.as_ref(), meta)?;
        let header = self.header();
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Xx3,
            &meta,
            self.local_transport_params,
        );

        let remote_bundle = self.remote_bundle.as_ref().ok_or(WireError::InvalidState)?;
        let (skem_ciphertext, skem_secret) =
            crypto.mlkem_encapsulate(&remote_bundle.mlkem_public_key);
        let skem_ciphertext =
            encrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &skem_ciphertext)?;
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        let static_bundle = encrypt_peer_bundle(crypto, &mut self.symmetric, &self.local.bundle())?;

        self.step = XxStep::Recv4;
        Ok(Xx3 {
            header,
            meta,
            transport_params: self.local_transport_params,
            skem_ciphertext,
            static_bundle,
        })
    }

    pub fn read_3(
        &mut self,
        crypto: &impl QlCrypto,
        now_seconds: u64,
        message: &Xx3,
    ) -> Result<(), WireError> {
        if self.step != XxStep::Recv3 {
            return Err(WireError::InvalidState);
        }
        message.meta.ensure_not_expired(now_seconds)?;
        require_handshake_meta(self.handshake_meta.as_ref(), message.meta)?;
        self.ensure_inbound_header(message.header)?;
        require_transport_params(
            self.remote_transport_params.as_ref(),
            message.transport_params,
        )?;
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            message.header,
            HandshakeKind::Xx3,
            &message.meta,
            message.transport_params,
        );

        let skem_ciphertext =
            decrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &message.skem_ciphertext)?;
        let skem_secret = crypto.mlkem_decapsulate(&self.local.mlkem_private_key, &skem_ciphertext);
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        let remote_bundle =
            decrypt_peer_bundle(crypto, &mut self.symmetric, &message.static_bundle)?;
        self.remote_bundle = Some(remote_bundle);
        self.step = XxStep::Send4;
        Ok(())
    }

    pub fn write_4(
        &mut self,
        crypto: &impl QlCrypto,
        meta: HandshakeMeta,
    ) -> Result<Xx4, WireError> {
        if self.step != XxStep::Send4 {
            return Err(WireError::InvalidState);
        }
        require_handshake_meta(self.handshake_meta.as_ref(), meta)?;
        let header = self.header();
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Xx4,
            &meta,
            self.local_transport_params,
        );

        let remote_bundle = self.remote_bundle.as_ref().ok_or(WireError::InvalidState)?;
        let (skem_ciphertext, skem_secret) =
            crypto.mlkem_encapsulate(&remote_bundle.mlkem_public_key);
        let skem_ciphertext =
            encrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &skem_ciphertext)?;
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        self.step = XxStep::Done;
        Ok(Xx4 {
            header,
            meta,
            transport_params: self.local_transport_params,
            skem_ciphertext,
        })
    }

    pub fn read_4(
        &mut self,
        crypto: &impl QlCrypto,
        now_seconds: u64,
        message: &Xx4,
    ) -> Result<(), WireError> {
        if self.step != XxStep::Recv4 {
            return Err(WireError::InvalidState);
        }
        message.meta.ensure_not_expired(now_seconds)?;
        require_handshake_meta(self.handshake_meta.as_ref(), message.meta)?;
        self.ensure_inbound_header(message.header)?;
        require_transport_params(
            self.remote_transport_params.as_ref(),
            message.transport_params,
        )?;
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            message.header,
            HandshakeKind::Xx4,
            &message.meta,
            message.transport_params,
        );

        let skem_ciphertext =
            decrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &message.skem_ciphertext)?;
        let skem_secret = crypto.mlkem_decapsulate(&self.local.mlkem_private_key, &skem_ciphertext);
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        self.step = XxStep::Done;
        Ok(())
    }

    pub fn finalize(self, crypto: &impl QlCrypto) -> Result<FinalizedHandshake, WireError> {
        if !self.is_finished() {
            return Err(WireError::InvalidState);
        }
        let remote_bundle = self.remote_bundle.ok_or(WireError::InvalidState)?;
        let remote_transport_params = self
            .remote_transport_params
            .ok_or(WireError::InvalidState)?;
        Ok(finalize_handshake(
            crypto,
            &self.symmetric,
            self.role,
            remote_bundle,
            remote_transport_params,
        ))
    }
}
