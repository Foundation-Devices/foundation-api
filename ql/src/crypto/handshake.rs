use bc_components::{
    Digest, MLDSAPublicKey, MLKEMCiphertext, MLKEMPublicKey, Nonce, SymmetricKey, XID,
};
use dcbor::CBOR;

use crate::{
    platform::QlPlatform,
    wire::handshake::{verify_transcript_signature, Confirm, Hello, HelloReply},
    QlError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponderSecrets {
    pub initiator_secret: SymmetricKey,
    pub responder_secret: SymmetricKey,
}

pub fn build_hello(
    platform: &impl QlPlatform,
    _sender: XID,
    _recipient: XID,
    recipient_encapsulation_key: &MLKEMPublicKey,
) -> Result<(Hello, SymmetricKey), QlError> {
    let nonce = next_nonce(platform);
    let (session_key, kem_ct) = recipient_encapsulation_key.encapsulate_new_shared_secret();
    Ok((Hello { nonce, kem_ct }, session_key))
}

pub fn respond_hello(
    platform: &impl QlPlatform,
    initiator: XID,
    responder: XID,
    initiator_encapsulation_key: &MLKEMPublicKey,
    hello: &Hello,
) -> Result<(HelloReply, ResponderSecrets), QlError> {
    let initiator_secret = platform
        .encapsulation_private_key()
        .decapsulate_shared_secret(&hello.kem_ct)
        .map_err(|_| QlError::InvalidPayload)?;
    let nonce = next_nonce(platform);
    let (responder_secret, kem_ct) = initiator_encapsulation_key.encapsulate_new_shared_secret();
    let transcript = handshake_transcript(initiator, responder, hello, &nonce, &kem_ct);
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
    platform: &impl QlPlatform,
    initiator: XID,
    responder: XID,
    responder_signing_key: &MLDSAPublicKey,
    hello: &Hello,
    reply: &HelloReply,
    initiator_secret: &SymmetricKey,
) -> Result<(Confirm, SymmetricKey), QlError> {
    let transcript = handshake_transcript(initiator, responder, hello, &reply.nonce, &reply.kem_ct);
    verify_transcript_signature(responder_signing_key, &reply.signature, &transcript)?;
    let responder_secret = platform
        .encapsulation_private_key()
        .decapsulate_shared_secret(&reply.kem_ct)
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
    reply: &HelloReply,
    confirm: &Confirm,
    secrets: &ResponderSecrets,
) -> Result<SymmetricKey, QlError> {
    let transcript = handshake_transcript(initiator, responder, hello, &reply.nonce, &reply.kem_ct);
    verify_transcript_signature(initiator_signing_key, &confirm.signature, &transcript)?;
    Ok(derive_session_key(
        &secrets.initiator_secret,
        &secrets.responder_secret,
        &transcript,
    ))
}
fn handshake_transcript(
    initiator: XID,
    responder: XID,
    hello: &Hello,
    responder_nonce: &Nonce,
    responder_kem_ct: &MLKEMCiphertext,
) -> Vec<u8> {
    CBOR::from(vec![
        CBOR::from(initiator),
        CBOR::from(responder),
        CBOR::from(hello.nonce.clone()),
        CBOR::from(responder_nonce.clone()),
        CBOR::from(hello.kem_ct.clone()),
        CBOR::from(responder_kem_ct.clone()),
    ])
    .to_cbor_data()
}

fn next_nonce(platform: &impl QlPlatform) -> Nonce {
    let mut data = [0u8; Nonce::NONCE_SIZE];
    platform.fill_random_bytes(&mut data);
    Nonce::from_data(data)
}

fn derive_session_key(
    initiator_secret: &SymmetricKey,
    responder_secret: &SymmetricKey,
    transcript: &[u8],
) -> SymmetricKey {
    let payload = CBOR::from(vec![
        CBOR::from(initiator_secret.as_bytes()),
        CBOR::from(responder_secret.as_bytes()),
        CBOR::from(transcript),
    ])
    .to_cbor_data();
    let digest = Digest::from_image(payload);
    SymmetricKey::from_data(*digest.data())
}
