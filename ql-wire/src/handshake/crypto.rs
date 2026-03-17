use bc_components::{
    Digest, MLDSAPublicKey, MLDSASignature, MLKEMCiphertext, MLKEMPublicKey, SymmetricKey,
};
use rkyv::{Archive, Serialize};

use super::{
    verify_signature, ArchivedConfirm, ArchivedHello, ArchivedHelloReply, ArchivedReady, Confirm,
    Hello, HelloReply, Ready, ReadyBody,
};
use crate::{
    access_value, deserialize_value, encode_value, encrypted_message::EncryptedMessage,
    ensure_not_expired, AsWireMlKemCiphertext, ControlMeta, Nonce, QlCrypto, QlHeader, QlIdentity,
    WireError, XID,
};

#[derive(Archive, Serialize)]
struct HelloProofData {
    initiator: XID,
    responder: XID,
    meta: ControlMeta,
    nonce: Nonce,
    #[rkyv(with = AsWireMlKemCiphertext)]
    kem_ct: bc_components::MLKEMCiphertext,
}

#[derive(Archive, Serialize)]
struct HandshakeTranscript {
    initiator: XID,
    responder: XID,
    hello_meta: ControlMeta,
    initiator_nonce: Nonce,
    responder_nonce: Nonce,
    reply_meta: ControlMeta,
    #[rkyv(with = AsWireMlKemCiphertext)]
    initiator_kem_ct: bc_components::MLKEMCiphertext,
    #[rkyv(with = AsWireMlKemCiphertext)]
    responder_kem_ct: bc_components::MLKEMCiphertext,
}

#[derive(Archive, Serialize)]
struct ConfirmProofData {
    meta: ControlMeta,
    transcript: Vec<u8>,
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
    crypto: &impl QlCrypto,
    identity: &QlIdentity,
    recipient: XID,
    recipient_encapsulation_key: &MLKEMPublicKey,
    meta: ControlMeta,
) -> Result<(Hello, SymmetricKey), WireError> {
    let nonce = next_nonce(crypto);
    let (session_key, kem_ct) = recipient_encapsulation_key.encapsulate_new_shared_secret();
    let signature = identity.signing_private_key.sign(hello_proof_data(
        identity.xid,
        recipient,
        &meta,
        &nonce,
        &kem_ct,
    ));
    Ok((
        Hello {
            meta,
            nonce,
            kem_ct,
            signature,
        },
        session_key,
    ))
}

pub fn verify_hello(
    initiator: XID,
    responder: XID,
    initiator_signing_key: &MLDSAPublicKey,
    hello: &ArchivedHello,
    now_seconds: u64,
) -> Result<(), WireError> {
    let meta: ControlMeta = (&hello.meta).into();
    ensure_not_expired(&meta, now_seconds)?;
    let signature = MLDSASignature::try_from(&hello.signature)?;
    let nonce: Nonce = deserialize_value(&hello.nonce)?;
    let kem_ct = MLKEMCiphertext::try_from(&hello.kem_ct)?;
    let proof_data = hello_proof_data(initiator, responder, &meta, &nonce, &kem_ct);
    verify_signature(initiator_signing_key, &signature, &proof_data)
}

pub fn respond_hello(
    crypto: &impl QlCrypto,
    identity: &QlIdentity,
    initiator: XID,
    initiator_signing_key: &MLDSAPublicKey,
    initiator_encapsulation_key: &MLKEMPublicKey,
    hello: &ArchivedHello,
    meta: ControlMeta,
    now_seconds: u64,
) -> Result<(HelloReply, ResponderSecrets), WireError> {
    verify_hello(
        initiator,
        identity.xid,
        initiator_signing_key,
        hello,
        now_seconds,
    )?;
    let hello_meta: ControlMeta = (&hello.meta).into();
    let initiator_nonce: Nonce = deserialize_value(&hello.nonce)?;
    let initiator_kem_ct = MLKEMCiphertext::try_from(&hello.kem_ct)?;
    let initiator_secret = identity
        .encapsulation_private_key
        .decapsulate_shared_secret(&initiator_kem_ct)
        .map_err(|_| WireError::InvalidPayload)?;
    let nonce = next_nonce(crypto);
    let (responder_secret, kem_ct) = initiator_encapsulation_key.encapsulate_new_shared_secret();
    let transcript = handshake_transcript(
        initiator,
        identity.xid,
        &hello_meta,
        &initiator_nonce,
        &initiator_kem_ct,
        &meta,
        &nonce,
        &kem_ct,
    );
    let signature = identity.signing_private_key.sign(&transcript);
    let reply = HelloReply {
        meta,
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
    identity: &QlIdentity,
    responder: XID,
    responder_signing_key: &MLDSAPublicKey,
    hello: &Hello,
    reply: &ArchivedHelloReply,
    initiator_secret: &SymmetricKey,
    meta: ControlMeta,
    now_seconds: u64,
) -> Result<(Confirm, SymmetricKey), WireError> {
    let reply_meta: ControlMeta = (&reply.meta).into();
    ensure_not_expired(&reply_meta, now_seconds)?;
    let reply_nonce: Nonce = deserialize_value(&reply.nonce)?;
    let reply_kem_ct = MLKEMCiphertext::try_from(&reply.kem_ct)?;
    let reply_signature = MLDSASignature::try_from(&reply.signature)?;
    let transcript = handshake_transcript(
        identity.xid,
        responder,
        &hello.meta,
        &hello.nonce,
        &hello.kem_ct,
        &reply_meta,
        &reply_nonce,
        &reply_kem_ct,
    );
    verify_signature(responder_signing_key, &reply_signature, &transcript)?;
    let responder_secret = identity
        .encapsulation_private_key
        .decapsulate_shared_secret(&reply_kem_ct)
        .map_err(|_| WireError::InvalidPayload)?;
    let signature = identity
        .signing_private_key
        .sign(confirm_proof_data(&meta, &transcript));
    let confirm = Confirm { meta, signature };
    let session_key = derive_session_key(initiator_secret, &responder_secret, &transcript);
    Ok((confirm, session_key))
}

pub fn finalize_confirm(
    initiator: XID,
    responder: XID,
    initiator_signing_key: &MLDSAPublicKey,
    hello: &Hello,
    reply: &HelloReply,
    confirm: &ArchivedConfirm,
    secrets: &ResponderSecrets,
    now_seconds: u64,
) -> Result<SymmetricKey, WireError> {
    verify_confirm(
        initiator,
        responder,
        initiator_signing_key,
        hello,
        reply,
        confirm,
        now_seconds,
    )?;
    Ok(derive_session_key(
        &secrets.initiator_secret,
        &secrets.responder_secret,
        &handshake_transcript(
            initiator,
            responder,
            &hello.meta,
            &hello.nonce,
            &hello.kem_ct,
            &reply.meta,
            &reply.nonce,
            &reply.kem_ct,
        ),
    ))
}

pub fn verify_confirm(
    initiator: XID,
    responder: XID,
    initiator_signing_key: &MLDSAPublicKey,
    hello: &Hello,
    reply: &HelloReply,
    confirm: &ArchivedConfirm,
    now_seconds: u64,
) -> Result<(), WireError> {
    let confirm_meta: ControlMeta = (&confirm.meta).into();
    ensure_not_expired(&confirm_meta, now_seconds)?;
    let confirm_signature = MLDSASignature::try_from(&confirm.signature)?;
    let transcript = handshake_transcript(
        initiator,
        responder,
        &hello.meta,
        &hello.nonce,
        &hello.kem_ct,
        &reply.meta,
        &reply.nonce,
        &reply.kem_ct,
    );
    let proof_data = confirm_proof_data(&confirm_meta, &transcript);
    verify_signature(initiator_signing_key, &confirm_signature, &proof_data)?;
    Ok(())
}

pub fn build_ready(
    crypto: &impl QlCrypto,
    header: QlHeader,
    session_key: &SymmetricKey,
    meta: ControlMeta,
    nonce: Nonce,
) -> Result<Ready, WireError> {
    let aad = header.aad();
    let body_bytes = encode_value(&ReadyBody { meta });
    Ok(Ready {
        encrypted: EncryptedMessage::encrypt(crypto, session_key, body_bytes, &aad, nonce)?,
    })
}

pub fn decrypt_ready(
    crypto: &impl QlCrypto,
    header: &QlHeader,
    ready: &mut ArchivedReady,
    session_key: &SymmetricKey,
    now_seconds: u64,
) -> Result<ReadyBody, WireError> {
    let aad = header.aad();
    let plaintext = ready.encrypted.decrypt(crypto, session_key, &aad)?;
    let body = access_value::<super::ArchivedReadyBody>(plaintext)?;
    let body = deserialize_value(body)?;
    ensure_not_expired(&body.meta, now_seconds)?;
    Ok(body)
}

fn handshake_transcript(
    initiator: XID,
    responder: XID,
    hello_meta: &ControlMeta,
    initiator_nonce: &Nonce,
    initiator_kem_ct: &bc_components::MLKEMCiphertext,
    reply_meta: &ControlMeta,
    responder_nonce: &Nonce,
    responder_kem_ct: &bc_components::MLKEMCiphertext,
) -> Vec<u8> {
    encode_value(&HandshakeTranscript {
        initiator,
        responder,
        hello_meta: *hello_meta,
        initiator_nonce: initiator_nonce.clone(),
        responder_nonce: responder_nonce.clone(),
        reply_meta: *reply_meta,
        initiator_kem_ct: initiator_kem_ct.clone(),
        responder_kem_ct: responder_kem_ct.clone(),
    })
}

fn hello_proof_data(
    initiator: XID,
    responder: XID,
    meta: &ControlMeta,
    nonce: &Nonce,
    kem_ct: &bc_components::MLKEMCiphertext,
) -> Vec<u8> {
    encode_value(&HelloProofData {
        initiator,
        responder,
        meta: *meta,
        nonce: nonce.clone(),
        kem_ct: kem_ct.clone(),
    })
}

fn confirm_proof_data(meta: &ControlMeta, transcript: &[u8]) -> Vec<u8> {
    encode_value(&ConfirmProofData {
        meta: *meta,
        transcript: transcript.to_vec(),
    })
}

fn next_nonce(platform: &impl QlCrypto) -> Nonce {
    let mut data = [0u8; Nonce::NONCE_SIZE];
    platform.fill_random_bytes(&mut data);
    Nonce(data)
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
