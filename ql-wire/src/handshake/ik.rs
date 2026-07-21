use std::borrow::Borrow;

use ql_codec::{ByteSlice, Encode};

use super::{
    decrypt_mlkem_ciphertext, decrypt_peer_bundle, encrypt_mlkem_ciphertext, encrypt_peer_bundle,
    finalize_handshake, generate_ephemeral_keypair, initialize_handshake_id,
    mix_hash_routed_handshake, require_handshake_id, EncryptedMlKemCiphertext, EncryptedPeerBundle,
    EphemeralKeyPair, EphemeralPublicKey, FinalizedHandshake, Role, RouteHeader, SymmetricState,
    TransportParams, PROTOCOL_IK, PROTOCOL_KK,
};
use crate::{
    Error, HandshakeId, HandshakeKind, MlKemCiphertext, MlKemPublicKey, PeerBundle, QlCrypto,
    QlIdentity,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ik1 {
    pub handshake_id: HandshakeId,
    pub transport_params: TransportParams,
    pub skem_ciphertext: MlKemCiphertext,
    pub ephemeral: EphemeralPublicKey,
    pub static_bundle: Option<EncryptedPeerBundle>,
}

impl Encode for Ik1 {
    fn encoded_len(&self) -> usize {
        HandshakeId::WIRE_SIZE
            + TransportParams::WIRE_SIZE
            + MlKemCiphertext::SIZE
            + EphemeralPublicKey::WIRE_SIZE
            + self
                .static_bundle
                .as_ref()
                .map_or(0, EncryptedPeerBundle::encoded_len)
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.handshake_id.encode(out);
        self.transport_params.encode(out);
        self.skem_ciphertext.encode(out);
        self.ephemeral.encode(out);
        if let Some(static_bundle) = self.static_bundle.as_ref() {
            static_bundle.encode(out);
        }
    }
}

impl<B: ByteSlice> ql_codec::Decode<B> for Ik1 {
    fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, ql_codec::Error> {
        let handshake_id = reader.decode()?;
        let transport_params = reader.decode()?;
        let skem_ciphertext = reader.decode()?;
        let ephemeral = reader.decode()?;
        let static_bundle = if reader.is_empty() {
            None
        } else {
            Some(reader.decode()?)
        };
        Ok(Self {
            handshake_id,
            transport_params,
            skem_ciphertext,
            ephemeral,
            static_bundle,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ik2 {
    pub handshake_id: HandshakeId,
    pub transport_params: TransportParams,
    pub ekem_ciphertext: MlKemCiphertext,
    pub skem_ciphertext: EncryptedMlKemCiphertext,
}

impl Encode for Ik2 {
    fn encoded_len(&self) -> usize {
        HandshakeId::WIRE_SIZE
            + TransportParams::WIRE_SIZE
            + MlKemCiphertext::SIZE
            + EncryptedMlKemCiphertext::WIRE_SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.handshake_id.encode(out);
        self.transport_params.encode(out);
        self.ekem_ciphertext.encode(out);
        self.skem_ciphertext.encode(out);
    }
}

impl<B: ByteSlice> ql_codec::Decode<B> for Ik2 {
    fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, ql_codec::Error> {
        Ok(Self {
            handshake_id: reader.decode()?,
            transport_params: reader.decode()?,
            ekem_ciphertext: reader.decode()?,
            skem_ciphertext: reader.decode()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Send1,
    Recv1,
    Send2,
    Recv2,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkPattern {
    Ik,
    Kk,
}

#[derive(Debug, Clone)]
pub struct IkHandshake<I = QlIdentity> {
    pattern: IkPattern,
    role: Role,
    step: Step,
    symmetric: SymmetricState,
    local: I,
    remote_bundle: Option<PeerBundle>,
    local_ephemeral: Option<EphemeralKeyPair>,
    remote_ephemeral: Option<EphemeralPublicKey>,
    handshake_id: Option<HandshakeId>,
    local_transport_params: TransportParams,
    remote_transport_params: Option<TransportParams>,
}

impl<I: Borrow<QlIdentity>> IkHandshake<I> {
    pub fn pattern(&self) -> IkPattern {
        self.pattern
    }

    pub fn handshake_id(&self) -> Option<HandshakeId> {
        self.handshake_id
    }

    pub fn local_ephemeral(&self) -> Option<&MlKemPublicKey> {
        self.local_ephemeral
            .as_ref()
            .map(|keypair| &keypair.mlkem.public)
    }

    pub fn new_ik_initiator(
        crypto: &impl QlCrypto,
        local: I,
        remote_bundle: PeerBundle,
        local_transport_params: TransportParams,
    ) -> Self {
        let mut symmetric = SymmetricState::new(crypto, PROTOCOL_IK);
        symmetric.mix_hash(crypto, &remote_bundle.encode_vec());
        Self::new(
            IkPattern::Ik,
            Role::Initiator,
            symmetric,
            local,
            Some(remote_bundle),
            local_transport_params,
        )
    }

    pub fn new_ik_responder(
        crypto: &impl QlCrypto,
        local: I,
        expected_remote: Option<PeerBundle>,
        local_transport_params: TransportParams,
    ) -> Self {
        let mut symmetric = SymmetricState::new(crypto, PROTOCOL_IK);
        symmetric.mix_hash(crypto, &local.borrow().bundle().encode_vec());
        Self::new(
            IkPattern::Ik,
            Role::Responder,
            symmetric,
            local,
            expected_remote,
            local_transport_params,
        )
    }

    pub fn new_kk_initiator(
        crypto: &impl QlCrypto,
        local: I,
        remote_bundle: PeerBundle,
        local_transport_params: TransportParams,
    ) -> Self {
        let mut symmetric = SymmetricState::new(crypto, PROTOCOL_KK);
        symmetric.mix_hash(crypto, &local.borrow().bundle().encode_vec());
        symmetric.mix_hash(crypto, &remote_bundle.encode_vec());
        Self::new(
            IkPattern::Kk,
            Role::Initiator,
            symmetric,
            local,
            Some(remote_bundle),
            local_transport_params,
        )
    }

    pub fn new_kk_responder(
        crypto: &impl QlCrypto,
        local: I,
        remote_bundle: PeerBundle,
        local_transport_params: TransportParams,
    ) -> Self {
        let mut symmetric = SymmetricState::new(crypto, PROTOCOL_KK);
        symmetric.mix_hash(crypto, &remote_bundle.encode_vec());
        symmetric.mix_hash(crypto, &local.borrow().bundle().encode_vec());
        Self::new(
            IkPattern::Kk,
            Role::Responder,
            symmetric,
            local,
            Some(remote_bundle),
            local_transport_params,
        )
    }

    fn new(
        pattern: IkPattern,
        role: Role,
        symmetric: SymmetricState,
        local: I,
        remote_bundle: Option<PeerBundle>,
        local_transport_params: TransportParams,
    ) -> Self {
        Self {
            pattern,
            role,
            step: match role {
                Role::Initiator => Step::Send1,
                Role::Responder => Step::Recv1,
            },
            symmetric,
            local,
            remote_bundle,
            local_ephemeral: None,
            remote_ephemeral: None,
            handshake_id: None,
            local_transport_params,
            remote_transport_params: None,
        }
    }
    pub fn is_finished(&self) -> bool {
        self.step == Step::Done
    }

    pub fn write_1(
        &mut self,
        crypto: &impl QlCrypto,
        handshake_id: HandshakeId,
    ) -> Result<Ik1, Error> {
        if self.step != Step::Send1 {
            return Err(Error::InvalidState);
        }
        initialize_handshake_id(&mut self.handshake_id, handshake_id)?;
        let remote_bundle = self.remote_bundle.as_ref().ok_or(Error::InvalidState)?;
        let local = self.local.borrow();
        let header = RouteHeader {
            sender: local.qid,
            recipient: remote_bundle.qid,
        };
        mix_hash_routed_handshake(
            &mut self.symmetric,
            crypto,
            header,
            match self.pattern {
                IkPattern::Ik => HandshakeKind::Ik1,
                IkPattern::Kk => HandshakeKind::Kk1,
            },
            handshake_id,
            self.local_transport_params,
        );

        let (skem_ciphertext, skem_secret) =
            crypto.mlkem_encapsulate(&remote_bundle.mlkem_public_key);
        self.symmetric.mix_hash(crypto, skem_ciphertext.as_bytes());
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        let local_ephemeral = generate_ephemeral_keypair(crypto);
        let ephemeral = local_ephemeral.public();
        self.symmetric.mix_hash_ephemeral(crypto, &ephemeral);

        let static_bundle = match self.pattern {
            IkPattern::Ik => Some(encrypt_peer_bundle(
                crypto,
                &mut self.symmetric,
                &local.bundle(),
            )?),
            IkPattern::Kk => None,
        };

        self.local_ephemeral = Some(local_ephemeral);
        self.step = Step::Recv2;
        Ok(Ik1 {
            handshake_id,
            transport_params: self.local_transport_params,
            skem_ciphertext,
            ephemeral,
            static_bundle,
        })
    }

    pub fn read_1(
        &mut self,
        crypto: &impl QlCrypto,
        header: RouteHeader,
        message: &Ik1,
    ) -> Result<(), Error> {
        if self.step != Step::Recv1 {
            return Err(Error::InvalidState);
        }
        initialize_handshake_id(&mut self.handshake_id, message.handshake_id)?;
        self.ensure_inbound_header(header)?;
        let local = self.local.borrow();
        mix_hash_routed_handshake(
            &mut self.symmetric,
            crypto,
            header,
            match self.pattern {
                IkPattern::Ik => HandshakeKind::Ik1,
                IkPattern::Kk => HandshakeKind::Kk1,
            },
            message.handshake_id,
            message.transport_params,
        );
        self.symmetric
            .mix_hash(crypto, message.skem_ciphertext.as_bytes());
        let skem_secret =
            crypto.mlkem_decapsulate(&local.mlkem_private_key, &message.skem_ciphertext);
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        self.symmetric
            .mix_hash_ephemeral(crypto, &message.ephemeral);
        self.remote_ephemeral = Some(message.ephemeral.clone());

        match (self.pattern, message.static_bundle.as_ref()) {
            (IkPattern::Ik, Some(static_bundle)) => {
                let remote_bundle =
                    decrypt_peer_bundle(crypto, &mut self.symmetric, static_bundle)?;
                if remote_bundle.qid != header.sender {
                    return Err(Error::InvalidRemoteBundle);
                }
                match self.remote_bundle.as_ref() {
                    Some(expected) if expected != &remote_bundle => {
                        return Err(Error::InvalidRemoteBundle);
                    }
                    Some(_) => {}
                    None => self.remote_bundle = Some(remote_bundle),
                }
            }
            (IkPattern::Kk, None) => {}
            _ => return Err(Error::InvalidState),
        }

        self.remote_transport_params = Some(message.transport_params);
        self.step = Step::Send2;
        Ok(())
    }

    pub fn write_2(
        &mut self,
        crypto: &impl QlCrypto,
        handshake_id: HandshakeId,
    ) -> Result<Ik2, Error> {
        if self.step != Step::Send2 {
            return Err(Error::InvalidState);
        }
        require_handshake_id(self.handshake_id.as_ref(), handshake_id)?;
        let remote_bundle = self.remote_bundle.as_ref().ok_or(Error::InvalidState)?;
        let header = RouteHeader {
            sender: self.local.borrow().qid,
            recipient: remote_bundle.qid,
        };
        mix_hash_routed_handshake(
            &mut self.symmetric,
            crypto,
            header,
            match self.pattern {
                IkPattern::Ik => HandshakeKind::Ik2,
                IkPattern::Kk => HandshakeKind::Kk2,
            },
            handshake_id,
            self.local_transport_params,
        );

        let remote_ephemeral = self.remote_ephemeral.as_ref().ok_or(Error::InvalidState)?;
        let (ekem_ciphertext, ekem_secret) =
            crypto.mlkem_encapsulate(&remote_ephemeral.mlkem_public_key);
        self.symmetric.mix_hash(crypto, ekem_ciphertext.as_bytes());
        self.symmetric.mix_key(crypto, ekem_secret.as_bytes());

        let (skem_ciphertext, skem_secret) =
            crypto.mlkem_encapsulate(&remote_bundle.mlkem_public_key);
        let skem_ciphertext =
            encrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &skem_ciphertext)?;
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        self.step = Step::Done;
        Ok(Ik2 {
            handshake_id,
            transport_params: self.local_transport_params,
            ekem_ciphertext,
            skem_ciphertext,
        })
    }

    pub fn read_2(
        &mut self,
        crypto: &impl QlCrypto,
        header: RouteHeader,
        message: &Ik2,
    ) -> Result<(), Error> {
        if self.step != Step::Recv2 {
            return Err(Error::InvalidState);
        }
        require_handshake_id(self.handshake_id.as_ref(), message.handshake_id)?;
        self.ensure_inbound_header(header)?;
        mix_hash_routed_handshake(
            &mut self.symmetric,
            crypto,
            header,
            match self.pattern {
                IkPattern::Ik => HandshakeKind::Ik2,
                IkPattern::Kk => HandshakeKind::Kk2,
            },
            message.handshake_id,
            message.transport_params,
        );

        let local_ephemeral = self.local_ephemeral.as_ref().ok_or(Error::InvalidState)?;
        self.symmetric
            .mix_hash(crypto, message.ekem_ciphertext.as_bytes());
        let ekem_secret =
            crypto.mlkem_decapsulate(&local_ephemeral.mlkem.private, &message.ekem_ciphertext);
        self.symmetric.mix_key(crypto, ekem_secret.as_bytes());

        let skem_ciphertext =
            decrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &message.skem_ciphertext)?;
        let skem_secret =
            crypto.mlkem_decapsulate(&self.local.borrow().mlkem_private_key, &skem_ciphertext);
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        self.remote_transport_params = Some(message.transport_params);
        self.step = Step::Done;
        Ok(())
    }

    pub fn finalize(self, crypto: &impl QlCrypto) -> Result<FinalizedHandshake, Error> {
        if !self.is_finished() {
            return Err(Error::InvalidState);
        }
        let remote_bundle = self.remote_bundle.ok_or(Error::InvalidState)?;
        let remote_transport_params = self.remote_transport_params.ok_or(Error::InvalidState)?;
        Ok(finalize_handshake(
            crypto,
            &self.symmetric,
            self.role,
            remote_bundle,
            remote_transport_params,
        ))
    }

    fn ensure_inbound_header(&self, header: RouteHeader) -> Result<(), Error> {
        if header.recipient != self.local.borrow().qid {
            return Err(Error::InvalidRouteHeader);
        }
        if let Some(remote_bundle) = self.remote_bundle.as_ref() {
            if header.sender != remote_bundle.qid {
                return Err(Error::InvalidRouteHeader);
            }
        }
        Ok(())
    }
}
