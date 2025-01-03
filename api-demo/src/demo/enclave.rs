#![allow(dead_code)]

use bc_xid::XIDDocument;
use gstp::{SealedRequest, SealedResponse};
use {
    anyhow::Result,
    bc_components::{PrivateKeyBase, PublicKeyBase, ARID},
    bc_envelope::prelude::*,
    foundation_abstracted::AbstractEnclave,
};

#[derive(Debug)]
pub struct Enclave {
    private_key: PrivateKeyBase,
    public_key: PublicKeyBase,
    xid_document: XIDDocument,
}

impl Enclave {
    pub fn new() -> Self {
        let private_key = PrivateKeyBase::new();
        let public_key = private_key.schnorr_public_key_base();
        Self {
            private_key: private_key.clone(),
            public_key,
            xid_document: XIDDocument::new_with_private_key(private_key),
        }
    }

    pub fn private_key(&self) -> &PrivateKeyBase {
        &self.private_key
    }
}

impl AbstractEnclave for Enclave {
    fn xid_document(&self) -> &XIDDocument {
        &self.xid_document
    }

    fn self_encrypt(&self, envelope: &Envelope) -> Envelope {
        envelope.encrypt_to_recipient(&self.public_key)
    }

    fn verify(&self, envelope: &Envelope) -> Result<Envelope> {
        envelope.verify(&self.public_key)
    }

    fn sign(&self, envelope: &Envelope) -> Envelope {
        envelope.sign(&self.private_key)
    }

    // fn seal(&self, envelope: &Envelope, recipient: &XIDDocument) -> Envelope {
    //     envelope.seal(&self.private_key, recipient.encryption_key().unwrap())
    // }

    fn decrypt(&self, envelope: &Envelope) -> Result<Envelope> {
        envelope.decrypt_to_recipient(&self.private_key)
    }

    // fn unseal(&self, envelope: &Envelope, sender: &XIDDocument) -> Result<Envelope> {
    //     envelope.unseal(sender, &self.private_key)
    // }

    fn self_decrypt(&self, envelope: &Envelope) -> Result<Envelope> {
        envelope.decrypt_to_recipient(&self.private_key)
    }

    fn sealed_request_to_envelope(&self, request: SealedRequest) -> Envelope {
        request.to_envelope(None, Some(&self.private_key), None).unwrap()
        //Envelope::from((request, &self.private_key))
    }

    fn sealed_request_and_recipient_to_envelope(
        &self,
        request: SealedRequest,
        recipient: &XIDDocument,
    ) -> Envelope {
        request.to_envelope(None, Some(&self.private_key), Some(recipient)).unwrap()
        //Envelope::from((request, &self.private_key, recipient))
    }

    fn sealed_response_to_envelope(&self, response: SealedResponse) -> Envelope {
        response.to_envelope(None, Some(&self.private_key), None).unwrap()
        //Envelope::from((response, &self.private_key))
    }

    fn envelope_to_sealed_request(&self, envelope: Envelope) -> Result<SealedRequest> {
        SealedRequest::try_from_envelope(&envelope, None, None, &self.private_key)
    }

    fn envelope_to_sealed_response(&self, envelope: Envelope) -> Result<SealedResponse> {
        SealedResponse::try_from_encrypted_envelope(&envelope, None, None, &self.private_key)
    }

    fn envelope_to_sealed_response_with_request_id(
        &self,
        envelope: Envelope,
        request_id: &ARID,
    ) -> Result<SealedResponse> {
        SealedResponse::try_from_encrypted_envelope(&envelope, Some(request_id), None, &self.private_key)
    }
}

#[cfg(test)]
pub mod tests {
    use {super::*, indoc::indoc};

    #[test]
    fn test_sign() {
        let enclave = Enclave::new();
        let envelope = Envelope::new("Hello, World!");
        let signed = enclave.sign(&envelope);
        assert_eq!(
            signed.format(),
            (indoc! {
                r#"
        {
            "Hello, World!"
        } [
            'verifiedBy': Signature
        ]
        "#
            })
            .trim()
        );
        let verified = enclave.verify(&signed).unwrap();
        assert!(envelope.is_identical_to(&verified));
    }

    // #[test]
    // fn test_encrypt() {
    //     let enclave = Enclave::new();
    //     let envelope = Envelope::new("Hello, World!");
    //     let encrypted = envelope.encrypt_to_recipient(enclave.xid_document());
    //     assert_eq!(
    //         encrypted.format(),
    //         (indoc! {
    //             r#"
    //     ENCRYPTED [
    //         'hasRecipient': SealedMessage
    //     ]
    //     "#
    //         })
    //         .trim()
    //     );
    //     let decrypted = enclave.decrypt(&encrypted).unwrap();
    //     assert!(envelope.is_identical_to(&decrypted));
    // }

    // #[test]
    // fn test_sign_and_encrypt() {
    //     let enclave1 = Enclave::new();
    //     let enclave2 = Enclave::new();
    //     let envelope = Envelope::new("Hello, World!");
    //     let signed_and_encrypted = enclave1.seal(&envelope, enclave2.xid_document());
    //     assert_eq!(
    //         signed_and_encrypted.format(),
    //         (indoc! {
    //             r#"
    //     ENCRYPTED [
    //         'hasRecipient': SealedMessage
    //     ]
    //     "#
    //         })
    //         .trim()
    //     );
    //     let verified_and_decrypted = enclave2
    //         .unseal(&signed_and_encrypted, enclave1.xid_document())
    //         .unwrap();
    //     assert!(envelope.is_identical_to(&verified_and_decrypted));
    // }

    #[test]
    fn test_self_encrypt() {
        let enclave = Enclave::new();
        let envelope = Envelope::new("Hello, World!");
        let encrypted = enclave.self_encrypt(&envelope);
        assert_eq!(
            encrypted.format(),
            (indoc! {
                r#"
        ENCRYPTED [
            'hasRecipient': SealedMessage
        ]
        "#
            })
            .trim()
        );
        let decrypted = enclave.self_decrypt(&encrypted).unwrap();
        assert!(envelope.is_identical_to(&decrypted));
    }
}
