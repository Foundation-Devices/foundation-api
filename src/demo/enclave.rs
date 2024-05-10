use bc_components::PublicKeyBase;
use bc_envelope::prelude::*;

pub trait Enclave {
    fn public_key(&self) -> &PublicKeyBase;

    fn sign(&self, envelope: &Envelope) -> Envelope;
    fn seal(&self, envelope: &Envelope, recipient: &PublicKeyBase) -> Envelope;
    fn self_encrypt(&self, envelope: &Envelope) -> Envelope;

    fn verify(&self, envelope: &Envelope) -> anyhow::Result<Envelope>;
    fn decrypt(&self, envelope: &Envelope) -> anyhow::Result<Envelope>;
    fn unseal(&self, envelope: &Envelope, sender: &PublicKeyBase) -> anyhow::Result<Envelope>;
    fn self_decrypt(&self, envelope: &Envelope) -> anyhow::Result<Envelope>;
}

#[allow(dead_code)]
pub trait EnclaveEnvelope {
    fn sign_with_enclave(&self, enclave: &impl Enclave) -> Envelope;
    fn seal_with_enclave(&self, enclave: &impl Enclave, recipient: &PublicKeyBase) -> Envelope;
    fn self_encrypt_with_enclave(&self, enclave: &impl Enclave) -> Envelope;

    fn verify_with_enclave(&self, enclave: &impl Enclave) -> anyhow::Result<Envelope>;
    fn decrypt_with_enclave(&self, enclave: &impl Enclave) -> anyhow::Result<Envelope>;
    fn unseal_with_enclave(&self, enclave: &impl Enclave, sender: &PublicKeyBase) -> anyhow::Result<Envelope>;
    fn self_decrypt_with_enclave(&self, enclave: &impl Enclave) -> anyhow::Result<Envelope>;
}

impl EnclaveEnvelope for Envelope {
    fn sign_with_enclave(&self, enclave: &impl Enclave) -> Envelope {
        enclave.sign(self)
    }

    fn seal_with_enclave(&self, enclave: &impl Enclave, recipient: &PublicKeyBase) -> Envelope {
        enclave.seal(self, recipient)
    }

    fn self_encrypt_with_enclave(&self, enclave: &impl Enclave) -> Envelope {
        enclave.self_encrypt(self)
    }

    fn verify_with_enclave(&self, enclave: &impl Enclave) -> anyhow::Result<Envelope> {
        enclave.verify(self)
    }

    fn decrypt_with_enclave(&self, enclave: &impl Enclave) -> anyhow::Result<Envelope> {
        enclave.decrypt(self)
    }

    fn unseal_with_enclave(&self, enclave: &impl Enclave, sender: &PublicKeyBase) -> anyhow::Result<Envelope> {
        enclave.unseal(self, sender)
    }

    fn self_decrypt_with_enclave(&self, enclave: &impl Enclave) -> anyhow::Result<Envelope> {
        enclave.self_decrypt(self)
    }
}
