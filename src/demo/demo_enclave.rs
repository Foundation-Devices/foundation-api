use bc_components::{PrivateKeyBase, PublicKeyBase};
use bc_envelope::prelude::*;

use crate::Enclave;

#[derive(Debug)]
pub struct DemoEnclave {
    private_key: PrivateKeyBase,
    public_key: PublicKeyBase,
}

impl DemoEnclave {
    pub fn new() -> Self {
        let private_key = PrivateKeyBase::new();
        let public_key = private_key.public_key();
        Self { private_key, public_key }
    }
}

impl Enclave for DemoEnclave {
    fn public_key(&self) -> &PublicKeyBase {
        &self.public_key
    }

    fn sign(&self, envelope: &Envelope) -> Envelope {
        envelope.sign(&self.private_key)
    }

    fn seal(&self, envelope: &Envelope, recipient: &PublicKeyBase) -> Envelope {
        envelope.seal(&self.private_key, recipient).unwrap()
    }

    fn self_encrypt(&self, envelope: &Envelope) -> Envelope {
        envelope.encrypt(&self.public_key).unwrap()
    }

    fn verify(&self, envelope: &Envelope) -> anyhow::Result<Envelope> {
        envelope.verify(&self.public_key)
    }

    fn decrypt(&self, envelope: &Envelope) -> anyhow::Result<Envelope> {
        envelope.decrypt(&self.private_key)
    }

    fn unseal(&self, envelope: &Envelope, sender: &PublicKeyBase) -> anyhow::Result<Envelope> {
        envelope.unseal(sender, &self.private_key)
    }

    fn self_decrypt(&self, envelope: &Envelope) -> anyhow::Result<Envelope> {
        envelope.decrypt(&self.private_key)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn test_sign() {
        let enclave = DemoEnclave::new();
        let envelope = Envelope::new("Hello, World!");
        let signed = enclave.sign(&envelope);
        assert_eq!(signed.format(), indoc! {r#"
        {
            "Hello, World!"
        } [
            'verifiedBy': Signature
        ]
        "#}.trim());
        let verified = enclave.verify(&signed).unwrap();
        assert!(envelope.is_identical_to(&verified));
    }

    #[test]
    fn test_encrypt() {
        let enclave = DemoEnclave::new();
        let envelope = Envelope::new("Hello, World!");
        let encrypted = envelope.encrypt(enclave.public_key()).unwrap();
        assert_eq!(encrypted.format(), indoc! {r#"
        ENCRYPTED [
            'hasRecipient': SealedMessage
        ]
        "#}.trim());
        let decrypted = enclave.decrypt(&encrypted).unwrap();
        assert!(envelope.is_identical_to(&decrypted));
    }

    #[test]
    fn test_sign_and_encrypt() {
        let enclave1 = DemoEnclave::new();
        let enclave2 = DemoEnclave::new();
        let envelope = Envelope::new("Hello, World!");
        let signed_and_encrypted = enclave1.seal(&envelope, enclave2.public_key());
        assert_eq!(signed_and_encrypted.format(), indoc! {r#"
        ENCRYPTED [
            'hasRecipient': SealedMessage
        ]
        "#}.trim());
        let verified_and_decrypted = enclave2.unseal(&signed_and_encrypted, enclave1.public_key()).unwrap();
        assert!(envelope.is_identical_to(&verified_and_decrypted));
    }

    #[test]
    fn test_self_encrypt() {
        let enclave = DemoEnclave::new();
        let envelope = Envelope::new("Hello, World!");
        let encrypted = enclave.self_encrypt(&envelope);
        assert_eq!(encrypted.format(), indoc! {r#"
        ENCRYPTED [
            'hasRecipient': SealedMessage
        ]
        "#}.trim());
        let decrypted = enclave.self_decrypt(&encrypted).unwrap();
        assert!(envelope.is_identical_to(&decrypted));
    }
}
