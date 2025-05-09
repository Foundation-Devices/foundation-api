#![allow(dead_code)]

use bc_components::{EncapsulationScheme, SignatureScheme};
use bc_xid::XIDDocument;
use gstp::{SealedRequest, SealedResponse};
use {
    anyhow::Result,
    bc_components::{PrivateKeys, PublicKeys, ARID},
    bc_envelope::prelude::*,
    foundation_abstracted::AbstractEnclave,
};

#[derive(Debug)]
pub struct Enclave {
    private_keys: PrivateKeys,
    public_keys: PublicKeys,
    xid_document: XIDDocument,
}

impl Enclave {
    pub fn new() -> Self {
        let (signing_private_key, signing_public_key) = SignatureScheme::MLDSA44.keypair();
        let (encapsulation_private_key, encapsulation_public_key) =
            EncapsulationScheme::MLKEM512.keypair();

        let private_keys = PrivateKeys::with_keys(signing_private_key, encapsulation_private_key);
        let public_keys = PublicKeys::new(signing_public_key, encapsulation_public_key);

        Self {
            private_keys,
            public_keys: public_keys.clone(),
            xid_document: XIDDocument::new(public_keys),
        }
    }

    pub fn private_keys(&self) -> &PrivateKeys {
        &self.private_keys
    }
}

impl AbstractEnclave for Enclave {
    fn xid_document(&self) -> &XIDDocument {
        &self.xid_document
    }

    fn self_encrypt(&self, envelope: &Envelope) -> Envelope {
        envelope.encrypt_to_recipient(&self.public_keys)
    }

    fn verify(&self, envelope: &Envelope) -> Result<Envelope> {
        envelope.verify(&self.public_keys)
    }

    fn sign(&self, envelope: &Envelope) -> Envelope {
        envelope.sign(&self.private_keys)
    }

    fn seal_response(&self, envelope: &SealedResponse, recipient: &XIDDocument) -> Envelope {
        envelope
            .to_envelope(None, Some(&self.private_keys), Some(recipient))
            .unwrap()
    }

    fn decrypt(&self, envelope: &Envelope) -> Result<Envelope> {
        envelope.decrypt_to_recipient(&self.private_keys)
    }

    // fn unseal(&self, envelope: &Envelope, sender: &XIDDocument) -> Result<Envelope> {
    //     envelope.unseal(sender, &self.private_key)
    // }

    fn self_decrypt(&self, envelope: &Envelope) -> Result<Envelope> {
        envelope.decrypt_to_recipient(&self.private_keys)
    }

    fn sealed_request_to_envelope(&self, request: SealedRequest) -> Envelope {
        request
            .to_envelope(None, Some(&self.private_keys), None)
            .unwrap()
        //Envelope::from((request, &self.private_key))
    }

    fn sealed_request_and_recipient_to_envelope(
        &self,
        request: SealedRequest,
        recipient: &XIDDocument,
    ) -> Envelope {
        request
            .to_envelope(None, Some(&self.private_keys), Some(recipient))
            .unwrap()
        //Envelope::from((request, &self.private_key, recipient))
    }

    fn sealed_response_to_envelope(&self, response: SealedResponse) -> Envelope {
        response
            .to_envelope(None, Some(&self.private_keys), None)
            .unwrap()
        //Envelope::from((response, &self.private_key))
    }

    fn envelope_to_sealed_request(&self, envelope: Envelope) -> Result<SealedRequest> {
        SealedRequest::try_from_envelope(&envelope, None, None, &self.private_keys)
    }

    fn envelope_to_sealed_response(&self, envelope: Envelope) -> Result<SealedResponse> {
        SealedResponse::try_from_encrypted_envelope(&envelope, None, None, &self.private_keys)
    }

    fn envelope_to_sealed_response_with_request_id(
        &self,
        envelope: Envelope,
        request_id: &ARID,
    ) -> Result<SealedResponse> {
        SealedResponse::try_from_encrypted_envelope(
            &envelope,
            Some(request_id),
            None,
            &self.private_keys,
        )
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
            'signed': Signature(MLDSA44)
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
            'hasRecipient': SealedMessage(MLKEM512)
        ]
        "#
            })
            .trim()
        );
        let decrypted = enclave.self_decrypt(&encrypted).unwrap();
        assert!(envelope.is_identical_to(&decrypted));
    }
}
