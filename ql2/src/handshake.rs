use bc_components::{
    Digest, EncapsulationCiphertext, EncapsulationPublicKey, Nonce, SigningPublicKey, SymmetricKey,
    XID,
};
use dcbor::CBOR;

use crate::{
    platform::QlPlatform,
    wire::{
        verify_transcript_signature, Confirm, HandshakeHeader, HandshakeKind, Hello, HelloReply,
    },
    QlError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponderSecrets {
    pub initiator_secret: SymmetricKey,
    pub responder_secret: SymmetricKey,
}

pub fn build_hello(
    platform: &impl QlPlatform,
    sender: XID,
    recipient: XID,
    recipient_encapsulation_key: &EncapsulationPublicKey,
) -> Result<(Hello, SymmetricKey), QlError> {
    let nonce = next_nonce(platform);
    let (session_key, kem_ct) = recipient_encapsulation_key.encapsulate_new_shared_secret();
    let header = HandshakeHeader {
        kind: HandshakeKind::Hello,
        sender,
        recipient,
    };
    Ok((
        Hello {
            header,
            nonce,
            kem_ct,
        },
        session_key,
    ))
}

pub fn respond_hello(
    platform: &impl QlPlatform,
    responder: XID,
    initiator_encapsulation_key: &EncapsulationPublicKey,
    hello: &Hello,
) -> Result<(HelloReply, ResponderSecrets), QlError> {
    if hello.header.kind != HandshakeKind::Hello || hello.header.recipient != responder {
        return Err(QlError::InvalidRole);
    }
    let initiator_secret = platform
        .encapsulation_private_key()
        .decapsulate_shared_secret(&hello.kem_ct)
        .map_err(|_| QlError::InvalidPayload)?;
    let nonce = next_nonce(platform);
    let (responder_secret, kem_ct) = initiator_encapsulation_key.encapsulate_new_shared_secret();
    let header = HandshakeHeader {
        kind: HandshakeKind::HelloReply,
        sender: responder,
        recipient: hello.header.sender,
    };
    let transcript = handshake_transcript(hello, &nonce, &kem_ct);
    let signature = platform
        .signer()
        .sign(&transcript)
        .map_err(|_| QlError::InvalidPayload)?;
    let reply = HelloReply {
        header,
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
    responder_signing_key: &SigningPublicKey,
    hello: &Hello,
    reply: &HelloReply,
    initiator_secret: &SymmetricKey,
) -> Result<(Confirm, SymmetricKey), QlError> {
    ensure_reply_matches(hello, reply)?;
    let transcript = handshake_transcript(hello, &reply.nonce, &reply.kem_ct);
    verify_transcript_signature(responder_signing_key, &reply.signature, &transcript)?;
    let responder_secret = platform
        .encapsulation_private_key()
        .decapsulate_shared_secret(&reply.kem_ct)
        .map_err(|_| QlError::InvalidPayload)?;
    let signature = platform
        .signer()
        .sign(&transcript)
        .map_err(|_| QlError::InvalidPayload)?;
    let confirm = Confirm {
        header: HandshakeHeader {
            kind: HandshakeKind::Confirm,
            sender: hello.header.sender,
            recipient: hello.header.recipient,
        },
        signature,
    };
    let session_key = derive_session_key(initiator_secret, &responder_secret, &transcript);
    Ok((confirm, session_key))
}

pub fn finalize_confirm(
    initiator_signing_key: &SigningPublicKey,
    hello: &Hello,
    reply: &HelloReply,
    confirm: &Confirm,
    secrets: &ResponderSecrets,
) -> Result<SymmetricKey, QlError> {
    ensure_reply_matches(hello, reply)?;
    if confirm.header.kind != HandshakeKind::Confirm
        || confirm.header.sender != hello.header.sender
        || confirm.header.recipient != hello.header.recipient
    {
        return Err(QlError::InvalidRole);
    }
    let transcript = handshake_transcript(hello, &reply.nonce, &reply.kem_ct);
    verify_transcript_signature(initiator_signing_key, &confirm.signature, &transcript)?;
    Ok(derive_session_key(
        &secrets.initiator_secret,
        &secrets.responder_secret,
        &transcript,
    ))
}

fn ensure_reply_matches(hello: &Hello, reply: &HelloReply) -> Result<(), QlError> {
    if reply.header.kind != HandshakeKind::HelloReply
        || reply.header.sender != hello.header.recipient
        || reply.header.recipient != hello.header.sender
    {
        return Err(QlError::InvalidRole);
    }
    Ok(())
}

fn handshake_transcript(
    hello: &Hello,
    responder_nonce: &bc_components::Nonce,
    responder_kem_ct: &EncapsulationCiphertext,
) -> Vec<u8> {
    CBOR::from(vec![
        CBOR::from(hello.header.sender),
        CBOR::from(hello.header.recipient),
        CBOR::from(hello.nonce.clone()),
        CBOR::from(responder_nonce.clone()),
        CBOR::from(hello.kem_ct.clone()),
        CBOR::from(responder_kem_ct.clone()),
    ])
    .to_cbor_data()
}

fn next_nonce(platform: &impl QlPlatform) -> Nonce {
    let mut data = [0u8; Nonce::NONCE_SIZE];
    platform.fill_bytes(&mut data);
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
