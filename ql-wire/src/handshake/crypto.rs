use super::{
    verify_signature, ArchivedConfirm, ArchivedHello, ArchivedHelloReply, ArchivedReady, Confirm,
    Hello, HelloReply, Ready, ReadyBody,
};
use crate::{
    access_value, deserialize_value, encode_value, encrypted_message::EncryptedMessage,
    ensure_not_expired, pq::ML_KEM_SUITE_TAG, ControlMeta, MlDsaPublicKey, MlKemCiphertext,
    MlKemPublicKey, Nonce, QlCrypto, QlHeader, QlIdentity, SessionKey, WireError, XID,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponderSecrets {
    pub initiator_secret: SessionKey,
    pub responder_secret: SessionKey,
}

pub fn build_hello(
    crypto: &impl QlCrypto,
    identity: &QlIdentity,
    recipient: XID,
    recipient_encapsulation_key: &MlKemPublicKey,
    meta: ControlMeta,
) -> Result<(Hello, SessionKey), WireError> {
    let nonce = next_nonce(crypto);
    let (session_key, kem_ct) =
        recipient_encapsulation_key.encapsulate_new_shared_secret(crypto)?;
    let proof_data = hash_hello_proof_data(crypto, identity.xid, recipient, &meta, &nonce, &kem_ct);
    let signature = identity.signing_private_key.sign(crypto, &proof_data)?;
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
    crypto: &impl QlCrypto,
    initiator: XID,
    responder: XID,
    initiator_signing_key: &MlDsaPublicKey,
    hello: &ArchivedHello,
    now_seconds: u64,
) -> Result<(), WireError> {
    let meta: ControlMeta = (&hello.meta).into();
    ensure_not_expired(&meta, now_seconds)?;
    let signature = deserialize_value(&hello.signature)?;
    let nonce: Nonce = deserialize_value(&hello.nonce)?;
    let kem_ct = deserialize_value(&hello.kem_ct)?;
    let proof_data = hash_hello_proof_data(crypto, initiator, responder, &meta, &nonce, &kem_ct);
    verify_signature(initiator_signing_key, &signature, &proof_data)
}

pub fn respond_hello(
    crypto: &impl QlCrypto,
    identity: &QlIdentity,
    initiator: XID,
    initiator_signing_key: &MlDsaPublicKey,
    initiator_encapsulation_key: &MlKemPublicKey,
    hello: &ArchivedHello,
    meta: ControlMeta,
    now_seconds: u64,
) -> Result<(HelloReply, ResponderSecrets), WireError> {
    verify_hello(
        crypto,
        initiator,
        identity.xid,
        initiator_signing_key,
        hello,
        now_seconds,
    )?;
    let hello_meta: ControlMeta = (&hello.meta).into();
    let initiator_nonce: Nonce = deserialize_value(&hello.nonce)?;
    let initiator_kem_ct = deserialize_value(&hello.kem_ct)?;
    let initiator_secret = identity
        .encapsulation_private_key
        .decapsulate_shared_secret(&initiator_kem_ct)?;
    let nonce = next_nonce(crypto);
    let (responder_secret, kem_ct) =
        initiator_encapsulation_key.encapsulate_new_shared_secret(crypto)?;
    let transcript = hash_handshake_transcript(
        crypto,
        initiator,
        identity.xid,
        &hello_meta,
        &initiator_nonce,
        &initiator_kem_ct,
        &meta,
        &nonce,
        &kem_ct,
    );
    let signature = identity.signing_private_key.sign(crypto, &transcript)?;
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
    crypto: &impl QlCrypto,
    identity: &QlIdentity,
    responder: XID,
    responder_signing_key: &MlDsaPublicKey,
    hello: &Hello,
    reply: &ArchivedHelloReply,
    initiator_secret: &SessionKey,
    meta: ControlMeta,
    now_seconds: u64,
) -> Result<(Confirm, SessionKey), WireError> {
    let reply_meta: ControlMeta = (&reply.meta).into();
    ensure_not_expired(&reply_meta, now_seconds)?;
    let reply_nonce: Nonce = deserialize_value(&reply.nonce)?;
    let reply_kem_ct = deserialize_value(&reply.kem_ct)?;
    let reply_signature = deserialize_value(&reply.signature)?;
    let transcript = hash_handshake_transcript(
        crypto,
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
        .decapsulate_shared_secret(&reply_kem_ct)?;
    let proof_data = hash_confirm_proof_data(
        crypto,
        &meta,
        identity.xid,
        responder,
        &hello.meta,
        &hello.nonce,
        &hello.kem_ct,
        &reply_meta,
        &reply_nonce,
        &reply_kem_ct,
    );
    let signature = identity.signing_private_key.sign(crypto, &proof_data)?;
    let confirm = Confirm { meta, signature };
    let session_key = derive_session_key(
        crypto,
        initiator_secret,
        &responder_secret,
        identity.xid,
        responder,
        &hello.meta,
        &hello.nonce,
        &hello.kem_ct,
        &reply_meta,
        &reply_nonce,
        &reply_kem_ct,
    );
    Ok((confirm, session_key))
}

pub fn finalize_confirm(
    crypto: &impl QlCrypto,
    initiator: XID,
    responder: XID,
    initiator_signing_key: &MlDsaPublicKey,
    hello: &Hello,
    reply: &HelloReply,
    confirm: &ArchivedConfirm,
    secrets: &ResponderSecrets,
    now_seconds: u64,
) -> Result<SessionKey, WireError> {
    verify_confirm(
        crypto,
        initiator,
        responder,
        initiator_signing_key,
        hello,
        reply,
        confirm,
        now_seconds,
    )?;
    Ok(derive_session_key(
        crypto,
        &secrets.initiator_secret,
        &secrets.responder_secret,
        initiator,
        responder,
        &hello.meta,
        &hello.nonce,
        &hello.kem_ct,
        &reply.meta,
        &reply.nonce,
        &reply.kem_ct,
    ))
}

pub fn verify_confirm(
    crypto: &impl QlCrypto,
    initiator: XID,
    responder: XID,
    initiator_signing_key: &MlDsaPublicKey,
    hello: &Hello,
    reply: &HelloReply,
    confirm: &ArchivedConfirm,
    now_seconds: u64,
) -> Result<(), WireError> {
    let confirm_meta: ControlMeta = (&confirm.meta).into();
    ensure_not_expired(&confirm_meta, now_seconds)?;
    let confirm_signature = deserialize_value(&confirm.signature)?;
    let proof_data = hash_confirm_proof_data(
        crypto,
        &confirm_meta,
        initiator,
        responder,
        &hello.meta,
        &hello.nonce,
        &hello.kem_ct,
        &reply.meta,
        &reply.nonce,
        &reply.kem_ct,
    );
    verify_signature(initiator_signing_key, &confirm_signature, &proof_data)?;
    Ok(())
}

pub fn build_ready(
    crypto: &impl QlCrypto,
    header: QlHeader,
    session_key: &SessionKey,
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
    session_key: &SessionKey,
    now_seconds: u64,
) -> Result<ReadyBody, WireError> {
    let aad = header.aad();
    let plaintext = ready.encrypted.decrypt(crypto, session_key, &aad)?;
    let body = access_value::<super::ArchivedReadyBody>(plaintext)?;
    let body = deserialize_value(body)?;
    ensure_not_expired(&body.meta, now_seconds)?;
    Ok(body)
}

fn hash_hello_proof_data(
    crypto: &impl QlCrypto,
    initiator: XID,
    responder: XID,
    meta: &ControlMeta,
    nonce: &Nonce,
    kem_ct: &MlKemCiphertext,
) -> [u8; 32] {
    let control_id = meta.control_id.0.to_le_bytes();
    let valid_until = meta.valid_until.to_le_bytes();
    crypto.hash(&[
        b"ql-wire:hello-proof:v1",
        b"initiator",
        &initiator.0,
        b"responder",
        &responder.0,
        b"control-id",
        &control_id,
        b"valid-until",
        &valid_until,
        b"nonce",
        &nonce.0,
        b"kem-suite",
        ML_KEM_SUITE_TAG,
        b"kem-ct",
        kem_ct.as_bytes(),
    ])
}

fn hash_handshake_transcript(
    crypto: &impl QlCrypto,
    initiator: XID,
    responder: XID,
    hello_meta: &ControlMeta,
    initiator_nonce: &Nonce,
    initiator_kem_ct: &MlKemCiphertext,
    reply_meta: &ControlMeta,
    responder_nonce: &Nonce,
    responder_kem_ct: &MlKemCiphertext,
) -> [u8; 32] {
    let hello_control_id = hello_meta.control_id.0.to_le_bytes();
    let hello_valid_until = hello_meta.valid_until.to_le_bytes();
    let reply_control_id = reply_meta.control_id.0.to_le_bytes();
    let reply_valid_until = reply_meta.valid_until.to_le_bytes();
    crypto.hash(&[
        b"ql-wire:handshake-transcript:v1",
        b"initiator",
        &initiator.0,
        b"responder",
        &responder.0,
        b"hello-control-id",
        &hello_control_id,
        b"hello-valid-until",
        &hello_valid_until,
        b"initiator-nonce",
        &initiator_nonce.0,
        b"initiator-kem-suite",
        ML_KEM_SUITE_TAG,
        b"initiator-kem-ct",
        initiator_kem_ct.as_bytes(),
        b"reply-control-id",
        &reply_control_id,
        b"reply-valid-until",
        &reply_valid_until,
        b"responder-nonce",
        &responder_nonce.0,
        b"responder-kem-suite",
        ML_KEM_SUITE_TAG,
        b"responder-kem-ct",
        responder_kem_ct.as_bytes(),
    ])
}

fn hash_confirm_proof_data(
    crypto: &impl QlCrypto,
    confirm_meta: &ControlMeta,
    initiator: XID,
    responder: XID,
    hello_meta: &ControlMeta,
    initiator_nonce: &Nonce,
    initiator_kem_ct: &MlKemCiphertext,
    reply_meta: &ControlMeta,
    responder_nonce: &Nonce,
    responder_kem_ct: &MlKemCiphertext,
) -> [u8; 32] {
    let confirm_control_id = confirm_meta.control_id.0.to_le_bytes();
    let confirm_valid_until = confirm_meta.valid_until.to_le_bytes();
    let hello_control_id = hello_meta.control_id.0.to_le_bytes();
    let hello_valid_until = hello_meta.valid_until.to_le_bytes();
    let reply_control_id = reply_meta.control_id.0.to_le_bytes();
    let reply_valid_until = reply_meta.valid_until.to_le_bytes();
    crypto.hash(&[
        b"ql-wire:confirm-proof:v1",
        b"confirm-control-id",
        &confirm_control_id,
        b"confirm-valid-until",
        &confirm_valid_until,
        b"initiator",
        &initiator.0,
        b"responder",
        &responder.0,
        b"hello-control-id",
        &hello_control_id,
        b"hello-valid-until",
        &hello_valid_until,
        b"initiator-nonce",
        &initiator_nonce.0,
        b"initiator-kem-suite",
        ML_KEM_SUITE_TAG,
        b"initiator-kem-ct",
        initiator_kem_ct.as_bytes(),
        b"reply-control-id",
        &reply_control_id,
        b"reply-valid-until",
        &reply_valid_until,
        b"responder-nonce",
        &responder_nonce.0,
        b"responder-kem-suite",
        ML_KEM_SUITE_TAG,
        b"responder-kem-ct",
        responder_kem_ct.as_bytes(),
    ])
}

fn next_nonce(crypto: &impl QlCrypto) -> Nonce {
    let mut data = [0u8; Nonce::NONCE_SIZE];
    crypto.fill_random_bytes(&mut data);
    Nonce(data)
}

fn derive_session_key(
    crypto: &impl QlCrypto,
    initiator_secret: &SessionKey,
    responder_secret: &SessionKey,
    initiator: XID,
    responder: XID,
    hello_meta: &ControlMeta,
    initiator_nonce: &Nonce,
    initiator_kem_ct: &MlKemCiphertext,
    reply_meta: &ControlMeta,
    responder_nonce: &Nonce,
    responder_kem_ct: &MlKemCiphertext,
) -> SessionKey {
    let hello_control_id = hello_meta.control_id.0.to_le_bytes();
    let hello_valid_until = hello_meta.valid_until.to_le_bytes();
    let reply_control_id = reply_meta.control_id.0.to_le_bytes();
    let reply_valid_until = reply_meta.valid_until.to_le_bytes();
    SessionKey::from_data(crypto.hash(&[
        b"ql-wire:session-key:v1",
        b"initiator-secret",
        initiator_secret.as_bytes(),
        b"responder-secret",
        responder_secret.as_bytes(),
        b"initiator",
        &initiator.0,
        b"responder",
        &responder.0,
        b"hello-control-id",
        &hello_control_id,
        b"hello-valid-until",
        &hello_valid_until,
        b"initiator-nonce",
        &initiator_nonce.0,
        b"initiator-kem-suite",
        ML_KEM_SUITE_TAG,
        b"initiator-kem-ct",
        initiator_kem_ct.as_bytes(),
        b"reply-control-id",
        &reply_control_id,
        b"reply-valid-until",
        &reply_valid_until,
        b"responder-nonce",
        &responder_nonce.0,
        b"responder-kem-suite",
        ML_KEM_SUITE_TAG,
        b"responder-kem-ct",
        responder_kem_ct.as_bytes(),
    ]))
}
