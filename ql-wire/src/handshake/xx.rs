use ql_common::QID;

use super::{
    decrypt_mlkem_ciphertext, decrypt_peer_bundle, encrypt_mlkem_ciphertext, encrypt_peer_bundle,
    finalize_handshake, generate_ephemeral_keypair, initialize_handshake_id,
    mix_hash_pairing_handshake, require_handshake_id, EncryptedMlKemCiphertext,
    EncryptedPeerBundle, EphemeralKeyPair, EphemeralPublicKey, FinalizedHandshake, Role,
    RouteHeader, SymmetricState, TransportParams,
};
use crate::{
    Error, HandshakeId, HandshakeKind, MlKemCiphertext, MlKemPublicKey, PairingId, PairingToken,
    PeerBundle, QlCrypto, QlIdentity,
};

const PROTOCOL_XX: &[u8] = b"ql-wire:pq-xx:v1";

ql_codec::codec_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Xx1 {
        pub handshake_id: HandshakeId,
        pub pairing_id: PairingId,
        pub transport_params: TransportParams,
        pub ephemeral: EphemeralPublicKey,
    }
}

ql_codec::codec_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Xx2 {
        pub handshake_id: HandshakeId,
        pub transport_params: TransportParams,
        pub ekem_ciphertext: MlKemCiphertext,
        pub static_bundle: EncryptedPeerBundle,
    }
}

ql_codec::codec_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Xx3 {
        pub handshake_id: HandshakeId,
        pub skem_ciphertext: EncryptedMlKemCiphertext,
        pub static_bundle: EncryptedPeerBundle,
    }
}

ql_codec::codec_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Xx4 {
        pub handshake_id: HandshakeId,
        pub skem_ciphertext: EncryptedMlKemCiphertext,
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
    remote_qid: QID,
    pairing_token: PairingToken,
    remote_bundle: Option<PeerBundle>,
    local_ephemeral: Option<EphemeralKeyPair>,
    remote_ephemeral: Option<EphemeralPublicKey>,
    handshake_id: Option<HandshakeId>,
    local_transport_params: TransportParams,
    remote_transport_params: Option<TransportParams>,
}

impl XxHandshake {
    pub fn new_initiator(
        crypto: &impl QlCrypto,
        local: QlIdentity,
        remote_qid: QID,
        pairing_token: PairingToken,
        local_transport_params: TransportParams,
    ) -> Self {
        Self {
            role: Role::Initiator,
            step: XxStep::Send1,
            symmetric: SymmetricState::new(crypto, PROTOCOL_XX),
            local,
            remote_qid,
            pairing_token,
            remote_bundle: None,
            local_ephemeral: None,
            remote_ephemeral: None,
            handshake_id: None,
            local_transport_params,
            remote_transport_params: None,
        }
    }

    pub fn new_responder(
        crypto: &impl QlCrypto,
        local: QlIdentity,
        remote_qid: QID,
        pairing_token: PairingToken,
        local_transport_params: TransportParams,
    ) -> Self {
        Self {
            role: Role::Responder,
            step: XxStep::Recv1,
            symmetric: SymmetricState::new(crypto, PROTOCOL_XX),
            local,
            remote_qid,
            pairing_token,
            remote_bundle: None,
            local_ephemeral: None,
            remote_ephemeral: None,
            handshake_id: None,
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

    pub fn pairing_id(&self, crypto: &impl QlCrypto) -> PairingId {
        self.pairing_token.id(crypto)
    }

    pub fn handshake_id(&self) -> Option<HandshakeId> {
        self.handshake_id
    }

    pub fn local_ephemeral(&self) -> Option<&MlKemPublicKey> {
        self.local_ephemeral
            .as_ref()
            .map(|keypair| &keypair.mlkem.public)
    }

    pub fn remote_qid(&self) -> QID {
        self.remote_qid
    }

    pub fn remote_bundle(&self) -> Option<&PeerBundle> {
        self.remote_bundle.as_ref()
    }

    fn header(&self) -> RouteHeader {
        RouteHeader {
            sender: self.local.qid,
            recipient: self.remote_qid,
        }
    }

    fn ensure_inbound_header(&self, header: RouteHeader) -> Result<(), Error> {
        if header.sender != self.remote_qid || header.recipient != self.local.qid {
            return Err(Error::InvalidRouteHeader);
        }
        Ok(())
    }

    fn ensure_remote_bundle(&self, bundle: &PeerBundle) -> Result<(), Error> {
        if bundle.qid == self.remote_qid {
            Ok(())
        } else {
            Err(Error::InvalidRemoteBundle)
        }
    }

    pub fn write_1(
        &mut self,
        crypto: &impl QlCrypto,
        handshake_id: HandshakeId,
    ) -> Result<Xx1, Error> {
        if self.step != XxStep::Send1 {
            return Err(Error::InvalidState);
        }
        initialize_handshake_id(&mut self.handshake_id, handshake_id)?;
        let header = self.header();
        let pairing_id = self.pairing_token.id(crypto);
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Xx1,
            handshake_id,
            pairing_id,
            self.local_transport_params,
        );
        self.symmetric
            .mix_psk_pairing_token(crypto, self.pairing_token);

        let local_ephemeral = generate_ephemeral_keypair(crypto);
        let ephemeral = local_ephemeral.public();
        self.symmetric.mix_hash_ephemeral(crypto, &ephemeral);

        self.local_ephemeral = Some(local_ephemeral);
        self.step = XxStep::Recv2;
        Ok(Xx1 {
            handshake_id,
            pairing_id,
            transport_params: self.local_transport_params,
            ephemeral,
        })
    }

    pub fn read_1(
        &mut self,
        crypto: &impl QlCrypto,
        header: RouteHeader,
        message: &Xx1,
    ) -> Result<(), Error> {
        if self.step != XxStep::Recv1 {
            return Err(Error::InvalidState);
        }
        initialize_handshake_id(&mut self.handshake_id, message.handshake_id)?;
        self.ensure_inbound_header(header)?;
        if message.pairing_id != self.pairing_token.id(crypto) {
            return Err(Error::InvalidPairingId);
        }
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Xx1,
            message.handshake_id,
            message.pairing_id,
            message.transport_params,
        );
        self.symmetric
            .mix_psk_pairing_token(crypto, self.pairing_token);
        self.symmetric
            .mix_hash_ephemeral(crypto, &message.ephemeral);

        self.remote_ephemeral = Some(message.ephemeral.clone());
        self.remote_transport_params = Some(message.transport_params);
        self.step = XxStep::Send2;
        Ok(())
    }

    pub fn write_2(
        &mut self,
        crypto: &impl QlCrypto,
        handshake_id: HandshakeId,
    ) -> Result<Xx2, Error> {
        if self.step != XxStep::Send2 {
            return Err(Error::InvalidState);
        }
        require_handshake_id(self.handshake_id.as_ref(), handshake_id)?;
        let header = self.header();
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Xx2,
            handshake_id,
            self.pairing_token.id(crypto),
            self.local_transport_params,
        );

        let remote_ephemeral = self.remote_ephemeral.as_ref().ok_or(Error::InvalidState)?;
        let (ekem_ciphertext, ekem_secret) =
            crypto.mlkem_encapsulate(&remote_ephemeral.mlkem_public_key);
        self.symmetric.mix_hash(crypto, ekem_ciphertext.as_bytes());
        self.symmetric.mix_key(crypto, ekem_secret.as_bytes());

        let static_bundle = encrypt_peer_bundle(crypto, &mut self.symmetric, &self.local.bundle())?;

        self.step = XxStep::Recv3;
        Ok(Xx2 {
            handshake_id,
            transport_params: self.local_transport_params,
            ekem_ciphertext,
            static_bundle,
        })
    }

    pub fn read_2(
        &mut self,
        crypto: &impl QlCrypto,
        header: RouteHeader,
        message: &Xx2,
    ) -> Result<(), Error> {
        if self.step != XxStep::Recv2 {
            return Err(Error::InvalidState);
        }
        require_handshake_id(self.handshake_id.as_ref(), message.handshake_id)?;
        self.ensure_inbound_header(header)?;
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Xx2,
            message.handshake_id,
            self.pairing_token.id(crypto),
            message.transport_params,
        );

        let local_ephemeral = self.local_ephemeral.as_ref().ok_or(Error::InvalidState)?;
        self.symmetric
            .mix_hash(crypto, message.ekem_ciphertext.as_bytes());
        let ekem_secret =
            crypto.mlkem_decapsulate(&local_ephemeral.mlkem.private, &message.ekem_ciphertext);
        self.symmetric.mix_key(crypto, ekem_secret.as_bytes());

        let remote_bundle =
            decrypt_peer_bundle(crypto, &mut self.symmetric, &message.static_bundle)?;
        self.ensure_remote_bundle(&remote_bundle)?;
        self.remote_bundle = Some(remote_bundle);
        self.remote_transport_params = Some(message.transport_params);
        self.step = XxStep::Send3;
        Ok(())
    }

    pub fn write_3(
        &mut self,
        crypto: &impl QlCrypto,
        handshake_id: HandshakeId,
    ) -> Result<Xx3, Error> {
        if self.step != XxStep::Send3 {
            return Err(Error::InvalidState);
        }
        require_handshake_id(self.handshake_id.as_ref(), handshake_id)?;
        let header = self.header();
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Xx3,
            handshake_id,
            self.pairing_token.id(crypto),
            self.local_transport_params,
        );

        let remote_bundle = self.remote_bundle.as_ref().ok_or(Error::InvalidState)?;
        let (skem_ciphertext, skem_secret) =
            crypto.mlkem_encapsulate(&remote_bundle.mlkem_public_key);
        let skem_ciphertext =
            encrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &skem_ciphertext)?;
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        let static_bundle = encrypt_peer_bundle(crypto, &mut self.symmetric, &self.local.bundle())?;

        self.step = XxStep::Recv4;
        Ok(Xx3 {
            handshake_id,
            skem_ciphertext,
            static_bundle,
        })
    }

    pub fn read_3(
        &mut self,
        crypto: &impl QlCrypto,
        header: RouteHeader,
        message: &Xx3,
    ) -> Result<(), Error> {
        if self.step != XxStep::Recv3 {
            return Err(Error::InvalidState);
        }
        require_handshake_id(self.handshake_id.as_ref(), message.handshake_id)?;
        self.ensure_inbound_header(header)?;
        let remote_transport_params = self.remote_transport_params.ok_or(Error::InvalidState)?;
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Xx3,
            message.handshake_id,
            self.pairing_token.id(crypto),
            remote_transport_params,
        );

        let skem_ciphertext =
            decrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &message.skem_ciphertext)?;
        let skem_secret = crypto.mlkem_decapsulate(&self.local.mlkem_private_key, &skem_ciphertext);
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        let remote_bundle =
            decrypt_peer_bundle(crypto, &mut self.symmetric, &message.static_bundle)?;
        self.ensure_remote_bundle(&remote_bundle)?;
        self.remote_bundle = Some(remote_bundle);
        self.step = XxStep::Send4;
        Ok(())
    }

    pub fn write_4(
        &mut self,
        crypto: &impl QlCrypto,
        handshake_id: HandshakeId,
    ) -> Result<Xx4, Error> {
        if self.step != XxStep::Send4 {
            return Err(Error::InvalidState);
        }
        require_handshake_id(self.handshake_id.as_ref(), handshake_id)?;
        let header = self.header();
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Xx4,
            handshake_id,
            self.pairing_token.id(crypto),
            self.local_transport_params,
        );

        let remote_bundle = self.remote_bundle.as_ref().ok_or(Error::InvalidState)?;
        let (skem_ciphertext, skem_secret) =
            crypto.mlkem_encapsulate(&remote_bundle.mlkem_public_key);
        let skem_ciphertext =
            encrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &skem_ciphertext)?;
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        self.step = XxStep::Done;
        Ok(Xx4 {
            handshake_id,
            skem_ciphertext,
        })
    }

    pub fn read_4(
        &mut self,
        crypto: &impl QlCrypto,
        header: RouteHeader,
        message: &Xx4,
    ) -> Result<(), Error> {
        if self.step != XxStep::Recv4 {
            return Err(Error::InvalidState);
        }
        require_handshake_id(self.handshake_id.as_ref(), message.handshake_id)?;
        self.ensure_inbound_header(header)?;
        let remote_transport_params = self.remote_transport_params.ok_or(Error::InvalidState)?;
        mix_hash_pairing_handshake(
            &mut self.symmetric,
            crypto,
            header,
            HandshakeKind::Xx4,
            message.handshake_id,
            self.pairing_token.id(crypto),
            remote_transport_params,
        );

        let skem_ciphertext =
            decrypt_mlkem_ciphertext(crypto, &mut self.symmetric, &message.skem_ciphertext)?;
        let skem_secret = crypto.mlkem_decapsulate(&self.local.mlkem_private_key, &skem_ciphertext);
        self.symmetric
            .mix_key_and_hash(crypto, skem_secret.as_bytes());

        self.step = XxStep::Done;
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
}
