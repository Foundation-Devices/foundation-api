use super::{
    decrypt_mlkem_ciphertext, decrypt_peer_bundle, encrypt_mlkem_ciphertext, encrypt_peer_bundle,
    finalize_handshake, generate_ephemeral_keypair, init_ik_symmetric, initialize_handshake_meta,
    mix_hash_ephemeral, mix_hash_routed_handshake, require_handshake_meta,
    EncryptedMlKemCiphertext, EncryptedPeerBundle, EphemeralKeyPair, EphemeralPublicKey,
    FinalizedHandshake, HandshakeHeader, Role, SymmetricState, TransportParams,
};
use crate::{
    codec, ByteSlice, HandshakeKind, HandshakeMeta, MlKemCiphertext, PeerBundle, QlCrypto,
    QlIdentity, WireEncode, WireError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ik1 {
    pub header: HandshakeHeader,
    pub meta: HandshakeMeta,
    pub transport_params: TransportParams,
    pub skem_ciphertext: MlKemCiphertext,
    pub ephemeral: EphemeralPublicKey,
    pub static_bundle: EncryptedPeerBundle,
}

impl Ik1 {
    pub const WIRE_SIZE: usize = HandshakeHeader::WIRE_SIZE
        + HandshakeMeta::WIRE_SIZE
        + TransportParams::WIRE_SIZE
        + MlKemCiphertext::SIZE
        + EphemeralPublicKey::WIRE_SIZE
        + EncryptedPeerBundle::WIRE_SIZE;
}

impl<B: ByteSlice> codec::WireDecode<B> for Ik1 {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            header: reader.decode()?,
            meta: reader.decode()?,
            transport_params: reader.decode()?,
            skem_ciphertext: reader.decode()?,
            ephemeral: reader.decode()?,
            static_bundle: reader.decode()?,
        })
    }
}

impl WireEncode for Ik1 {
    fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.header.encode(out);
        self.meta.encode(out);
        self.transport_params.encode(out);
        self.skem_ciphertext.encode(out);
        self.ephemeral.encode(out);
        self.static_bundle.encode(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ik2 {
    pub header: HandshakeHeader,
    pub meta: HandshakeMeta,
    pub transport_params: TransportParams,
    pub ekem_ciphertext: MlKemCiphertext,
    pub skem_ciphertext: EncryptedMlKemCiphertext,
}

impl Ik2 {
    pub const WIRE_SIZE: usize = HandshakeHeader::WIRE_SIZE
        + HandshakeMeta::WIRE_SIZE
        + TransportParams::WIRE_SIZE
        + MlKemCiphertext::SIZE
        + EncryptedMlKemCiphertext::WIRE_SIZE;
}

impl<B: ByteSlice> codec::WireDecode<B> for Ik2 {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            header: reader.decode()?,
            meta: reader.decode()?,
            transport_params: reader.decode()?,
            ekem_ciphertext: reader.decode()?,
            skem_ciphertext: reader.decode()?,
        })
    }
}

impl WireEncode for Ik2 {
    fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.header.encode(out);
        self.meta.encode(out);
        self.transport_params.encode(out);
        self.ekem_ciphertext.encode(out);
        self.skem_ciphertext.encode(out);
    }
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
    local_transport_params: TransportParams,
    remote_transport_params: Option<TransportParams>,
}

impl IkHandshake {
    pub fn new_initiator(
        crypto: &impl QlCrypto,
        local: QlIdentity,
        remote_bundle: PeerBundle,
        local_transport_params: TransportParams,
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
            local_transport_params,
            remote_transport_params: None,
        }
    }

    pub fn new_responder(
        crypto: &impl QlCrypto,
        local: QlIdentity,
        expected_remote: Option<PeerBundle>,
        local_transport_params: TransportParams,
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
            local_transport_params,
            remote_transport_params: None,
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

    pub fn write_1(
        &mut self,
        crypto: &impl QlCrypto,
        meta: HandshakeMeta,
    ) -> Result<Ik1, WireError> {
        if self.step != IkStep::Send1 {
            return Err(WireError::InvalidState);
        }
        initialize_handshake_meta(&mut self.handshake_meta, meta)?;
        let remote_bundle = self.remote_bundle.as_ref().ok_or(WireError::InvalidState)?;
        let header = self.outbound_header()?;
        mix_hash_routed_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Ik1,
            &meta,
            self.local_transport_params,
        );
        let (skem_ciphertext, skem_secret) =
            crypto.mlkem_encapsulate(&remote_bundle.mlkem_public_key);
        self.symmetric.mix_hash(crypto, skem_ciphertext.as_bytes());
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        let local_ephemeral = generate_ephemeral_keypair(crypto);
        let public = local_ephemeral.public();
        mix_hash_ephemeral(&mut self.symmetric, crypto, &public);

        let static_bundle = encrypt_peer_bundle(crypto, &mut self.symmetric, &self.local.bundle())?;

        self.local_ephemeral = Some(local_ephemeral);
        self.step = IkStep::Recv2;
        Ok(Ik1 {
            header,
            meta,
            transport_params: self.local_transport_params,
            skem_ciphertext,
            ephemeral: public,
            static_bundle,
        })
    }

    pub fn write_2(
        &mut self,
        crypto: &impl QlCrypto,
        meta: HandshakeMeta,
    ) -> Result<Ik2, WireError> {
        if self.step != IkStep::Send2 {
            return Err(WireError::InvalidState);
        }
        require_handshake_meta(self.handshake_meta.as_ref(), meta)?;
        let header = self.outbound_header()?;
        mix_hash_routed_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Ik2,
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

        let remote_bundle = self.remote_bundle.as_ref().ok_or(WireError::InvalidState)?;
        let (skem_ciphertext, skem_secret) =
            crypto.mlkem_encapsulate(&remote_bundle.mlkem_public_key);
        let skem_ciphertext =
            encrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &skem_ciphertext)?;
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        self.step = IkStep::Done;
        Ok(Ik2 {
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
        message: &Ik1,
    ) -> Result<(), WireError> {
        if self.step != IkStep::Recv1 {
            return Err(WireError::InvalidState);
        }
        initialize_handshake_meta(&mut self.handshake_meta, message.meta)?;
        self.ensure_inbound_recipient(message.header)?;
        self.ensure_known_remote_sender(message.header)?;
        mix_hash_routed_handshake(
            &mut self.symmetric,
            crypto,
            message.header,
            HandshakeKind::Ik1,
            &message.meta,
            message.transport_params,
        );
        self.symmetric
            .mix_hash(crypto, message.skem_ciphertext.as_bytes());
        let skem_secret =
            crypto.mlkem_decapsulate(&self.local.mlkem_private_key, &message.skem_ciphertext);
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
        self.remote_transport_params = Some(message.transport_params);
        self.step = IkStep::Send2;
        Ok(())
    }

    pub fn read_2(
        &mut self,
        crypto: &impl QlCrypto,
        message: &Ik2,
    ) -> Result<(), WireError> {
        if self.step != IkStep::Recv2 {
            return Err(WireError::InvalidState);
        }
        require_handshake_meta(self.handshake_meta.as_ref(), message.meta)?;
        self.ensure_inbound_recipient(message.header)?;
        self.ensure_known_remote_sender(message.header)?;
        mix_hash_routed_handshake(
            &mut self.symmetric,
            crypto,
            message.header,
            HandshakeKind::Ik2,
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
        self.step = IkStep::Done;
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
