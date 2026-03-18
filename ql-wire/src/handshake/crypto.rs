use zerocopy::{
    byte_slice::{ByteSlice, ByteSliceMut},
    Ref,
};

use super::{Confirm, ConfirmWire, Hello, HelloReply, HelloReplyWire, HelloWire, Ready, ReadyBody};
use crate::{
    pq::ML_KEM_SUITE_TAG, ControlMeta, EncryptedMessage, EncryptedMessageWire, MlDsaPublicKey,
    MlDsaSignature, MlKemCiphertext, MlKemPublicKey, Nonce, QlCrypto, QlHeader, QlIdentity,
    SessionKey, WireError, XID,
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
    let proof_data = hash_hello_proof_data(
        crypto,
        identity.xid,
        recipient,
        &meta,
        &nonce.0,
        kem_ct.as_bytes(),
    );
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

pub fn verify_hello<B: ByteSlice>(
    crypto: &impl QlCrypto,
    initiator: XID,
    responder: XID,
    initiator_signing_key: &MlDsaPublicKey,
    hello: &Ref<B, HelloWire>,
    now_seconds: u64,
) -> Result<(), WireError> {
    let meta = ControlMeta::from_wire(hello.meta);
    meta.ensure_not_expired(now_seconds)?;
    let proof_data = hash_hello_proof_data(
        crypto,
        initiator,
        responder,
        &meta,
        &hello.nonce,
        &hello.kem_ct,
    );
    verify_signature_bytes(initiator_signing_key, &hello.signature, &proof_data)
}

pub fn respond_hello<B: ByteSlice>(
    crypto: &impl QlCrypto,
    identity: &QlIdentity,
    initiator: XID,
    initiator_signing_key: &MlDsaPublicKey,
    initiator_encapsulation_key: &MlKemPublicKey,
    hello: &Ref<B, HelloWire>,
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
    let initiator_secret = identity
        .encapsulation_private_key
        .decapsulate_shared_secret_bytes(&hello.kem_ct)?;
    let hello_meta = ControlMeta::from_wire(hello.meta);
    let nonce = next_nonce(crypto);
    let (responder_secret, kem_ct) =
        initiator_encapsulation_key.encapsulate_new_shared_secret(crypto)?;
    let transcript = hash_handshake_transcript(
        crypto,
        initiator,
        identity.xid,
        &hello_meta,
        &hello.nonce,
        &hello.kem_ct,
        &meta,
        &nonce.0,
        kem_ct.as_bytes(),
    );
    let signature = identity.signing_private_key.sign(crypto, &transcript)?;
    Ok((
        HelloReply {
            meta,
            nonce,
            kem_ct,
            signature,
        },
        ResponderSecrets {
            initiator_secret,
            responder_secret,
        },
    ))
}

pub fn build_confirm<B: ByteSlice>(
    crypto: &impl QlCrypto,
    identity: &QlIdentity,
    responder: XID,
    responder_signing_key: &MlDsaPublicKey,
    hello: &Hello,
    reply: &Ref<B, HelloReplyWire>,
    initiator_secret: &SessionKey,
    meta: ControlMeta,
    now_seconds: u64,
) -> Result<(Confirm, SessionKey), WireError> {
    let reply_meta = ControlMeta::from_wire(reply.meta);
    reply_meta.ensure_not_expired(now_seconds)?;
    let transcript = hash_handshake_transcript(
        crypto,
        identity.xid,
        responder,
        &hello.meta,
        &hello.nonce.0,
        hello.kem_ct.as_bytes(),
        &reply_meta,
        &reply.nonce,
        &reply.kem_ct,
    );
    verify_signature_bytes(responder_signing_key, &reply.signature, &transcript)?;
    let responder_secret = identity
        .encapsulation_private_key
        .decapsulate_shared_secret_bytes(&reply.kem_ct)?;
    let proof_data = hash_confirm_proof_data(
        crypto,
        &meta,
        identity.xid,
        responder,
        &hello.meta,
        &hello.nonce.0,
        hello.kem_ct.as_bytes(),
        &reply_meta,
        &reply.nonce,
        &reply.kem_ct,
    );
    let signature = identity.signing_private_key.sign(crypto, &proof_data)?;
    let session_key = derive_session_key(
        crypto,
        initiator_secret,
        &responder_secret,
        identity.xid,
        responder,
        &hello.meta,
        &hello.nonce.0,
        hello.kem_ct.as_bytes(),
        &reply_meta,
        &reply.nonce,
        &reply.kem_ct,
    );
    Ok((Confirm { meta, signature }, session_key))
}

pub fn finalize_confirm<B: ByteSlice>(
    crypto: &impl QlCrypto,
    initiator: XID,
    responder: XID,
    initiator_signing_key: &MlDsaPublicKey,
    hello: &Hello,
    reply: &HelloReply,
    confirm: &Ref<B, ConfirmWire>,
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
        &hello.nonce.0,
        hello.kem_ct.as_bytes(),
        &reply.meta,
        &reply.nonce.0,
        reply.kem_ct.as_bytes(),
    ))
}

pub fn verify_confirm<B: ByteSlice>(
    crypto: &impl QlCrypto,
    initiator: XID,
    responder: XID,
    initiator_signing_key: &MlDsaPublicKey,
    hello: &Hello,
    reply: &HelloReply,
    confirm: &Ref<B, ConfirmWire>,
    now_seconds: u64,
) -> Result<(), WireError> {
    let confirm_meta = ControlMeta::from_wire(confirm.meta);
    confirm_meta.ensure_not_expired(now_seconds)?;
    let proof_data = hash_confirm_proof_data(
        crypto,
        &confirm_meta,
        initiator,
        responder,
        &hello.meta,
        &hello.nonce.0,
        hello.kem_ct.as_bytes(),
        &reply.meta,
        &reply.nonce.0,
        reply.kem_ct.as_bytes(),
    );
    verify_signature_bytes(initiator_signing_key, &confirm.signature, &proof_data)
}

pub fn build_ready(
    crypto: &impl QlCrypto,
    header: QlHeader,
    session_key: &SessionKey,
    meta: ControlMeta,
    nonce: Nonce,
) -> Result<Ready, WireError> {
    let aad = header.aad();
    let body_bytes = ReadyBody { meta }.encode();
    Ok(Ready {
        encrypted: EncryptedMessage::encrypt(crypto, session_key, body_bytes, &aad, nonce)?,
    })
}

pub fn decrypt_ready<B: ByteSliceMut>(
    crypto: &impl QlCrypto,
    header: &QlHeader,
    ready: &mut Ref<B, EncryptedMessageWire>,
    session_key: &SessionKey,
    now_seconds: u64,
) -> Result<ReadyBody, WireError> {
    let aad = header.aad();
    let plaintext = EncryptedMessage::decrypt_in_place(ready, crypto, session_key, &aad)?;
    let body = ReadyBody::decode(plaintext)?;
    body.meta.ensure_not_expired(now_seconds)?;
    Ok(body)
}

fn hash_hello_proof_data(
    crypto: &impl QlCrypto,
    initiator: XID,
    responder: XID,
    meta: &ControlMeta,
    nonce: &[u8; Nonce::SIZE],
    kem_ct: &[u8; MlKemCiphertext::SIZE],
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
        nonce,
        b"kem-suite",
        ML_KEM_SUITE_TAG,
        b"kem-ct",
        kem_ct,
    ])
}

fn hash_handshake_transcript(
    crypto: &impl QlCrypto,
    initiator: XID,
    responder: XID,
    hello_meta: &ControlMeta,
    initiator_nonce: &[u8; Nonce::SIZE],
    initiator_kem_ct: &[u8; MlKemCiphertext::SIZE],
    reply_meta: &ControlMeta,
    responder_nonce: &[u8; Nonce::SIZE],
    responder_kem_ct: &[u8; MlKemCiphertext::SIZE],
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
        initiator_nonce,
        b"initiator-kem-suite",
        ML_KEM_SUITE_TAG,
        b"initiator-kem-ct",
        initiator_kem_ct,
        b"reply-control-id",
        &reply_control_id,
        b"reply-valid-until",
        &reply_valid_until,
        b"responder-nonce",
        responder_nonce,
        b"responder-kem-suite",
        ML_KEM_SUITE_TAG,
        b"responder-kem-ct",
        responder_kem_ct,
    ])
}

fn hash_confirm_proof_data(
    crypto: &impl QlCrypto,
    confirm_meta: &ControlMeta,
    initiator: XID,
    responder: XID,
    hello_meta: &ControlMeta,
    initiator_nonce: &[u8; Nonce::SIZE],
    initiator_kem_ct: &[u8; MlKemCiphertext::SIZE],
    reply_meta: &ControlMeta,
    responder_nonce: &[u8; Nonce::SIZE],
    responder_kem_ct: &[u8; MlKemCiphertext::SIZE],
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
        initiator_nonce,
        b"initiator-kem-suite",
        ML_KEM_SUITE_TAG,
        b"initiator-kem-ct",
        initiator_kem_ct,
        b"reply-control-id",
        &reply_control_id,
        b"reply-valid-until",
        &reply_valid_until,
        b"responder-nonce",
        responder_nonce,
        b"responder-kem-suite",
        ML_KEM_SUITE_TAG,
        b"responder-kem-ct",
        responder_kem_ct,
    ])
}

fn next_nonce(crypto: &impl QlCrypto) -> Nonce {
    let mut data = [0u8; Nonce::SIZE];
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
    initiator_nonce: &[u8; Nonce::SIZE],
    initiator_kem_ct: &[u8; MlKemCiphertext::SIZE],
    reply_meta: &ControlMeta,
    responder_nonce: &[u8; Nonce::SIZE],
    responder_kem_ct: &[u8; MlKemCiphertext::SIZE],
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
        initiator_nonce,
        b"initiator-kem-suite",
        ML_KEM_SUITE_TAG,
        b"initiator-kem-ct",
        initiator_kem_ct,
        b"reply-control-id",
        &reply_control_id,
        b"reply-valid-until",
        &reply_valid_until,
        b"responder-nonce",
        responder_nonce,
        b"responder-kem-suite",
        ML_KEM_SUITE_TAG,
        b"responder-kem-ct",
        responder_kem_ct,
    ]))
}

fn verify_signature_bytes(
    signing_key: &MlDsaPublicKey,
    signature: &[u8; MlDsaSignature::SIZE],
    proof_data: &[u8],
) -> Result<(), WireError> {
    if signing_key.verify_bytes(signature, proof_data) {
        Ok(())
    } else {
        Err(WireError::InvalidSignature)
    }
}
