#![allow(dead_code)]

use anyhow::Result;
use bc_components::{PrivateKeyBase, PublicKeyBase, ARID};
use bc_envelope::prelude::*;

#[derive(Debug)]
pub struct Enclave {
    private_key: PrivateKeyBase,
    public_key: PublicKeyBase,
}

impl Enclave {
    pub fn new() -> Self {
        let private_key = PrivateKeyBase::new();
        let public_key = private_key.public_key();
        Self { private_key, public_key }
    }
}

impl Enclave {
    pub fn public_key(&self) -> &PublicKeyBase {
        &self.public_key
    }
}

/// Private key operations
impl Enclave {
    pub fn sign(&self, envelope: &Envelope) -> Envelope {
        envelope.sign(&self.private_key)
    }

    pub fn seal(&self, envelope: &Envelope, recipient: &PublicKeyBase) -> Envelope {
        envelope.seal(&self.private_key, recipient)
    }

    pub fn self_encrypt(&self, envelope: &Envelope) -> Envelope {
        envelope.encrypt_to_recipient(&self.public_key)
    }

    pub fn verify(&self, envelope: &Envelope) -> Result<Envelope> {
        envelope.verify(&self.public_key)
    }

    pub fn decrypt(&self, envelope: &Envelope) -> Result<Envelope> {
        envelope.decrypt_to_recipient(&self.private_key)
    }

    pub fn unseal(&self, envelope: &Envelope, sender: &PublicKeyBase) -> Result<Envelope> {
        envelope.unseal(sender, &self.private_key)
    }

    pub fn self_decrypt(&self, envelope: &Envelope) -> Result<Envelope> {
        envelope.decrypt_to_recipient(&self.private_key)
    }
}

//
// Infallable conversions using the enclave
//

pub trait SecureInto<T>: Sized {
    fn secure_into(self, enclave: &Enclave) -> T;
}

pub trait SecureFrom<T>: Sized {
    fn secure_from(value: T, enclave: &Enclave) -> Self;
}

impl<T, U> SecureInto<U> for T where U: SecureFrom<T> {
    fn secure_into(self, enclave: &Enclave) -> U {
        U::secure_from(self, enclave)
    }
}

//
// Fallable conversions using the enclave
//

pub trait SecureTryInto<T>: Sized {
    type Error;

    fn secure_try_into(self, enclave: &Enclave) -> Result<T, Self::Error>;
}

pub trait SecureTryFrom<T>: Sized {
    type Error;

    fn secure_try_from(value: T, enclave: &Enclave) -> Result<Self, Self::Error>;
}

impl<T, U> SecureTryInto<U> for T where U: SecureTryFrom<T> {
    type Error = <U as SecureTryFrom<T>>::Error;

    fn secure_try_into(self, enclave: &Enclave) -> Result<U, Self::Error> {
        U::secure_try_from(self, enclave)
    }
}

//
// Request -> Envelope
//

impl SecureFrom<SealedRequest> for Envelope {
    fn secure_from(value: SealedRequest, enclave: &Enclave) -> Self {
        Self::from((value, &enclave.private_key))
    }
}

impl SecureFrom<(SealedRequest, &PublicKeyBase)> for Envelope {
    fn secure_from((value, recipient): (SealedRequest, &PublicKeyBase), enclave: &Enclave) -> Self {
        Self::from((value, &enclave.private_key, recipient))
    }
}

//
// Response -> Envelope
//

impl SecureFrom<SealedResponse> for Envelope {
    fn secure_from(value: SealedResponse, enclave: &Enclave) -> Self {
        Self::from((value, &enclave.private_key))
    }
}

//
// Envelope -> Request
//

impl SecureTryFrom<Envelope> for SealedRequest {
    type Error = anyhow::Error;

    fn secure_try_from(value: Envelope, enclave: &Enclave) -> Result<Self, Self::Error> {
        SealedRequest::try_from((value, &enclave.private_key))
    }
}

//
// Envelope -> Response
//

impl SecureTryFrom<(Envelope, &ARID)> for SealedResponse {
    type Error = anyhow::Error;

    fn secure_try_from((value, request_id): (Envelope, &ARID), enclave: &Enclave) -> Result<Self, Self::Error> {
        SealedResponse::try_from((value, Some(request_id), None, &enclave.private_key))
    }
}

impl SecureTryFrom<Envelope> for SealedResponse {
    type Error = anyhow::Error;

    fn secure_try_from(value: Envelope, enclave: &Enclave) -> Result<Self, Self::Error> {
        SealedResponse::try_from((value, None, None, &enclave.private_key))
    }
}


#[cfg(test)]
pub mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn test_sign() {
        let enclave = Enclave::new();
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
        let enclave = Enclave::new();
        let envelope = Envelope::new("Hello, World!");
        let encrypted = envelope.encrypt_to_recipient(enclave.public_key());
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
        let enclave1 = Enclave::new();
        let enclave2 = Enclave::new();
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
        let enclave = Enclave::new();
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
