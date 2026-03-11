use bc_components::{Digest, MLDSAPublicKey, MLKEMPublicKey, Nonce, SymmetricKey, XID};
use rkyv::{Archive, Serialize};

use super::{
    verify_transcript_signature, ArchivedConfirm, ArchivedHello, ArchivedHelloReply, Confirm,
    Hello, HelloReply,
};
use crate::{
    platform::QlCrypto,
    wire::{
        encode_value, mldsa_signature_from_archived, mlkem_ciphertext_from_archived,
        nonce_from_archived, AsWireMlKemCiphertext, AsWireNonce, AsWireXid,
    },
    QlError,
};

#[derive(Archive, Serialize)]
struct HandshakeTranscript {
    #[rkyv(with = AsWireXid)]
    initiator: XID,
    #[rkyv(with = AsWireXid)]
    responder: XID,
    #[rkyv(with = AsWireNonce)]
    initiator_nonce: Nonce,
    #[rkyv(with = AsWireNonce)]
    responder_nonce: Nonce,
    #[rkyv(with = AsWireMlKemCiphertext)]
    initiator_kem_ct: bc_components::MLKEMCiphertext,
    #[rkyv(with = AsWireMlKemCiphertext)]
    responder_kem_ct: bc_components::MLKEMCiphertext,
}

#[derive(Archive, Serialize)]
struct SessionKeyMaterial {
    initiator_secret: Vec<u8>,
    responder_secret: Vec<u8>,
    transcript: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponderSecrets {
    pub initiator_secret: SymmetricKey,
    pub responder_secret: SymmetricKey,
}

pub fn build_hello(
    platform: &impl QlCrypto,
    _sender: XID,
    _recipient: XID,
    recipient_encapsulation_key: &MLKEMPublicKey,
) -> Result<(Hello, SymmetricKey), QlError> {
    let nonce = next_nonce(platform);
    let (session_key, kem_ct) = recipient_encapsulation_key.encapsulate_new_shared_secret();
    Ok((Hello { nonce, kem_ct }, session_key))
}

pub fn respond_hello(
    platform: &impl QlCrypto,
    initiator: XID,
    responder: XID,
    initiator_encapsulation_key: &MLKEMPublicKey,
    hello: &ArchivedHello,
) -> Result<(HelloReply, ResponderSecrets), QlError> {
    let initiator_nonce = nonce_from_archived(&hello.nonce);
    let initiator_kem_ct = mlkem_ciphertext_from_archived(&hello.kem_ct)?;
    let initiator_secret = platform
        .encapsulation_private_key()
        .decapsulate_shared_secret(&initiator_kem_ct)
        .map_err(|_| QlError::InvalidPayload)?;
    let nonce = next_nonce(platform);
    let (responder_secret, kem_ct) = initiator_encapsulation_key.encapsulate_new_shared_secret();
    let transcript = handshake_transcript(
        initiator,
        responder,
        &initiator_nonce,
        &nonce,
        &initiator_kem_ct,
        &kem_ct,
    );
    let signature = platform.signing_private_key().sign(&transcript);
    let reply = HelloReply {
        nonce,
        kem_ct,
        signature,
    };
    Ok((
        reply,
        ResponderSecrets {
            initiator_secret,
            responder_secret,
        },
    ))
}

pub fn build_confirm(
    platform: &impl QlCrypto,
    initiator: XID,
    responder: XID,
    responder_signing_key: &MLDSAPublicKey,
    hello: &Hello,
    reply: &ArchivedHelloReply,
    initiator_secret: &SymmetricKey,
) -> Result<(Confirm, SymmetricKey), QlError> {
    let reply_nonce = nonce_from_archived(&reply.nonce);
    let reply_kem_ct = mlkem_ciphertext_from_archived(&reply.kem_ct)?;
    let reply_signature = mldsa_signature_from_archived(&reply.signature)?;
    let transcript = handshake_transcript(
        initiator,
        responder,
        &hello.nonce,
        &reply_nonce,
        &hello.kem_ct,
        &reply_kem_ct,
    );
    verify_transcript_signature(responder_signing_key, &reply_signature, &transcript)?;
    let responder_secret = platform
        .encapsulation_private_key()
        .decapsulate_shared_secret(&reply_kem_ct)
        .map_err(|_| QlError::InvalidPayload)?;
    let signature = platform.signing_private_key().sign(&transcript);
    let confirm = Confirm { signature };
    let session_key = derive_session_key(initiator_secret, &responder_secret, &transcript);
    Ok((confirm, session_key))
}

pub fn finalize_confirm(
    initiator: XID,
    responder: XID,
    initiator_signing_key: &MLDSAPublicKey,
    hello: &Hello,
    reply: &super::HelloReply,
    confirm: &ArchivedConfirm,
    secrets: &ResponderSecrets,
) -> Result<SymmetricKey, QlError> {
    let confirm_signature = mldsa_signature_from_archived(&confirm.signature)?;
    let transcript = handshake_transcript(
        initiator,
        responder,
        &hello.nonce,
        &reply.nonce,
        &hello.kem_ct,
        &reply.kem_ct,
    );
    verify_transcript_signature(initiator_signing_key, &confirm_signature, &transcript)?;
    Ok(derive_session_key(
        &secrets.initiator_secret,
        &secrets.responder_secret,
        &transcript,
    ))
}

fn handshake_transcript(
    initiator: XID,
    responder: XID,
    initiator_nonce: &Nonce,
    responder_nonce: &Nonce,
    initiator_kem_ct: &bc_components::MLKEMCiphertext,
    responder_kem_ct: &bc_components::MLKEMCiphertext,
) -> Vec<u8> {
    encode_value(&HandshakeTranscript {
        initiator,
        responder,
        initiator_nonce: initiator_nonce.clone(),
        responder_nonce: responder_nonce.clone(),
        initiator_kem_ct: initiator_kem_ct.clone(),
        responder_kem_ct: responder_kem_ct.clone(),
    })
}

fn next_nonce(platform: &impl QlCrypto) -> Nonce {
    let mut data = [0u8; Nonce::NONCE_SIZE];
    platform.fill_random_bytes(&mut data);
    Nonce::from_data(data)
}

fn derive_session_key(
    initiator_secret: &SymmetricKey,
    responder_secret: &SymmetricKey,
    transcript: &[u8],
) -> SymmetricKey {
    let payload = encode_value(&SessionKeyMaterial {
        initiator_secret: initiator_secret.as_bytes().to_vec(),
        responder_secret: responder_secret.as_bytes().to_vec(),
        transcript: transcript.to_vec(),
    });
    let digest = Digest::from_image(payload);
    SymmetricKey::from_data(*digest.data())
}
