use anyhow::Result;
use bc_components::ARID;
use bc_envelope::prelude::*;
use bc_xid::XIDDocument;
use gstp::{SealedRequest, SealedResponse};

pub trait AbstractEnclave {
    // Public key operations
    fn xid_document(&self) -> &XIDDocument;
    fn self_encrypt(&self, envelope: &Envelope) -> Envelope;
    fn verify(&self, envelope: &Envelope) -> Result<Envelope>;

    // Private key operations
    fn sign(&self, envelope: &Envelope) -> Envelope;
    fn seal_response(&self, envelope: &SealedResponse, recipient: &XIDDocument) -> Envelope;
    fn decrypt(&self, envelope: &Envelope) -> Result<Envelope>;
    //fn unseal(&self, envelope: &Envelope, sender: &XIDDocument) ->
    // Result<Envelope>;
    fn self_decrypt(&self, envelope: &Envelope) -> Result<Envelope>;

    // Request -> Envelope
    fn sealed_request_to_envelope(&self, request: SealedRequest) -> Envelope;
    fn sealed_request_and_recipient_to_envelope(
        &self,
        request: SealedRequest,
        recipient: &XIDDocument,
    ) -> Envelope;

    // Response -> Envelope
    fn sealed_response_to_envelope(&self, response: SealedResponse) -> Envelope;

    // Envelope -> Request
    fn envelope_to_sealed_request(&self, envelope: Envelope) -> Result<SealedRequest>;

    // Envelope -> Response
    fn envelope_to_sealed_response(&self, envelope: Envelope) -> Result<SealedResponse>;
    fn envelope_to_sealed_response_with_request_id(
        &self,
        envelope: Envelope,
        request_id: &ARID,
    ) -> Result<SealedResponse>;
}

//
// Infallable conversions using an enclave
//

pub trait SecureInto<T, E>: Sized
where
    E: AbstractEnclave,
{
    fn secure_into(self, enclave: &E) -> T;
}

pub trait SecureFrom<T, E>: Sized
where
    E: AbstractEnclave,
{
    fn secure_from(value: T, enclave: &E) -> Self;
}

impl<T, U, E> SecureInto<U, E> for T
where
    U: SecureFrom<T, E>,
    E: AbstractEnclave,
{
    fn secure_into(self, enclave: &E) -> U {
        U::secure_from(self, enclave)
    }
}

//
// Fallable conversions using an enclave
//

pub trait SecureTryInto<T, E>: Sized
where
    E: AbstractEnclave,
{
    type Error;

    fn secure_try_into(self, enclave: &E) -> Result<T, Self::Error>;
}

pub trait SecureTryFrom<T, E>: Sized
where
    Self: Sized,
    E: AbstractEnclave,
{
    type Error;

    fn secure_try_from(value: T, enclave: &E) -> Result<Self, Self::Error>;
}

impl<T, U, E> SecureTryInto<U, E> for T
where
    U: SecureTryFrom<T, E>,
    E: AbstractEnclave,
{
    type Error = <U as SecureTryFrom<T, E>>::Error;

    fn secure_try_into(self, enclave: &E) -> Result<U, Self::Error> {
        U::secure_try_from(self, enclave)
    }
}

//
// Request -> Envelope
//

impl<E> SecureFrom<SealedRequest, E> for Envelope
where
    E: AbstractEnclave,
{
    fn secure_from(value: SealedRequest, enclave: &E) -> Self {
        enclave.sealed_request_to_envelope(value)
    }
}

impl<E> SecureFrom<(SealedRequest, &XIDDocument), E> for Envelope
where
    E: AbstractEnclave,
{
    fn secure_from((value, recipient): (SealedRequest, &XIDDocument), enclave: &E) -> Self {
        enclave.sealed_request_and_recipient_to_envelope(value, recipient)
    }
}

//
// Response -> Envelope
//

impl<E> SecureFrom<SealedResponse, E> for Envelope
where
    E: AbstractEnclave,
{
    fn secure_from(value: SealedResponse, enclave: &E) -> Self {
        enclave.sealed_response_to_envelope(value)
    }
}

//
// Envelope -> Request
//

impl<E> SecureTryFrom<Envelope, E> for SealedRequest
where
    E: AbstractEnclave,
{
    type Error = anyhow::Error;

    fn secure_try_from(value: Envelope, enclave: &E) -> Result<Self, Self::Error> {
        enclave.envelope_to_sealed_request(value)
    }
}

//
// Envelope -> Response
//

impl<E> SecureTryFrom<Envelope, E> for SealedResponse
where
    E: AbstractEnclave,
{
    type Error = anyhow::Error;

    fn secure_try_from(value: Envelope, enclave: &E) -> Result<Self, Self::Error> {
        enclave.envelope_to_sealed_response(value)
    }
}

impl<E> SecureTryFrom<(Envelope, &ARID), E> for SealedResponse
where
    E: AbstractEnclave,
{
    type Error = anyhow::Error;

    fn secure_try_from(
        (value, request_id): (Envelope, &ARID),
        enclave: &E,
    ) -> Result<Self, Self::Error> {
        enclave.envelope_to_sealed_response_with_request_id(value, request_id)
    }
}
