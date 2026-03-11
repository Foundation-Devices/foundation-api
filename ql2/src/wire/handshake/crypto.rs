use bc_components::{Digest, MLDSAPublicKey, MLKEMPublicKey, Nonce, SymmetricKey, XID};
use rkyv::{Archive, Serialize};

use super::{verify_transcript_signature, Confirm, Hello, HelloReply};
use crate::{
    platform::QlCrypto,
    wire::{encode_value, AsWireMlKemCiphertext, AsWireNonce, AsWireXid},
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

pub fn respond_hello<H>(
    platform: &impl QlCrypto,
    initiator: XID,
    responder: XID,
    initiator_encapsulation_key: &MLKEMPublicKey,
    hello: H,
) -> Result<(HelloReply, ResponderSecrets), QlError>
where
    H: TryInto<Hello, Error = QlError>,
{
    let hello = hello.try_into()?;
    let initiator_secret = platform
        .encapsulation_private_key()
        .decapsulate_shared_secret(&hello.kem_ct)
        .map_err(|_| QlError::InvalidPayload)?;
    let nonce = next_nonce(platform);
    let (responder_secret, kem_ct) = initiator_encapsulation_key.encapsulate_new_shared_secret();
    let transcript = handshake_transcript(initiator, responder, &hello, &nonce, &kem_ct);
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

pub fn build_confirm<R>(
    platform: &impl QlCrypto,
    initiator: XID,
    responder: XID,
    responder_signing_key: &MLDSAPublicKey,
    hello: &Hello,
    reply: R,
    initiator_secret: &SymmetricKey,
) -> Result<(Confirm, SymmetricKey), QlError>
where
    R: TryInto<HelloReply, Error = QlError>,
{
    let reply = reply.try_into()?;
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

pub fn finalize_confirm<C>(
    initiator: XID,
    responder: XID,
    initiator_signing_key: &MLDSAPublicKey,
    hello: &Hello,
    reply: &HelloReply,
    confirm: C,
    secrets: &ResponderSecrets,
) -> Result<SymmetricKey, QlError>
where
    C: TryInto<Confirm, Error = QlError>,
{
    let confirm = confirm.try_into()?;
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
    responder_kem_ct: &bc_components::MLKEMCiphertext,
) -> Vec<u8> {
    encode_value(&HandshakeTranscript {
        initiator,
        responder,
        initiator_nonce: hello.nonce.clone(),
        responder_nonce: responder_nonce.clone(),
        initiator_kem_ct: hello.kem_ct.clone(),
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
