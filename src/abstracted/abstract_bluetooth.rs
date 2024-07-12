use {
    crate::{AbstractEnclave, BluetoothEndpoint, SecureFrom, SecureTryFrom},
    anyhow::Result,
    async_trait::async_trait,
    bc_components::{PublicKeyBase, ARID},
    bc_envelope::prelude::*,
    tokio::time::Duration,
};

#[async_trait]
pub trait AbstractBluetoothChannel {
    fn endpoint(&self) -> &BluetoothEndpoint;
    async fn send(&self, message: impl Into<Vec<u8>> + std::marker::Send) -> Result<()>;
    async fn receive(&self, timeout: Duration) -> Result<Vec<u8>>;

    async fn send_envelope(&self, envelope: &Envelope) -> Result<()> {
        self.send(envelope.to_cbor_data()).await
    }

    async fn receive_envelope(&self, timeout: Duration) -> Result<Envelope> {
        let bytes = self.receive(timeout).await?;
        Envelope::try_from_cbor_data(bytes)
    }

    async fn send_request_with_id<E, S>(
        &self,
        recipient: &PublicKeyBase,
        enclave: &E,
        request_id: &ARID,
        body: Expression,
        state: Option<S>,
    ) -> Result<()>
    where
        S: EnvelopeEncodable + Send + Sync,
        E: AbstractEnclave + Send + Sync,
    {
        let request = SealedRequest::new_with_body(body, request_id, enclave.public_key())
            .with_optional_state(state);
        let sent_envelope = Envelope::secure_from((request, recipient), enclave);
        self.send_envelope(&sent_envelope).await
    }

    async fn send_request<E, S>(
        &self,
        recipient: &PublicKeyBase,
        enclave: &E,
        body: Expression,
        state: Option<S>,
    ) -> Result<()>
    where
        S: EnvelopeEncodable + Send + Sync,
        E: AbstractEnclave + Send + Sync,
    {
        self.send_request_with_id(recipient, enclave, &ARID::new(), body, state)
            .await
    }

    async fn call<E, S>(
        &self,
        recipient: &PublicKeyBase,
        enclave: &E,
        body: Expression,
        state: Option<S>,
    ) -> Result<SealedResponse>
    where
        S: EnvelopeEncodable + Send + Sync,
        E: AbstractEnclave + Send + Sync,
    {
        let request_id = ARID::new();
        self.send_request_with_id(recipient, enclave, &request_id, body, state)
            .await?;

        let received_envelope = self.receive_envelope(Duration::from_secs(10)).await?;
        let response = SealedResponse::secure_try_from((received_envelope, &request_id), enclave)?;
        Ok(response)
    }

    async fn send_ok_response<E>(
        &self,
        recipient: &PublicKeyBase,
        enclave: &E,
        id: &ARID,
        result: Option<Envelope>,
        peer_continuation: Option<&Envelope>,
    ) -> Result<()>
    where
        E: AbstractEnclave + Send + Sync,
    {
        let response = SealedResponse::new_success(id, enclave.public_key())
            .with_optional_result(result)
            .with_peer_continuation(peer_continuation);
        self.send_response(recipient, enclave, response).await
    }

    async fn send_error_response<E>(
        &self,
        recipient: &PublicKeyBase,
        enclave: &E,
        id: &ARID,
        error: &str,
        peer_continuation: Option<&Envelope>,
    ) -> Result<()>
    where
        E: AbstractEnclave + Send + Sync,
    {
        let response = SealedResponse::new_failure(id, enclave.public_key())
            .with_error(error)
            .with_peer_continuation(peer_continuation);
        self.send_response(recipient, enclave, response).await
    }

    async fn send_response<E>(
        &self,
        recipient: &PublicKeyBase,
        enclave: &E,
        response: SealedResponse,
    ) -> Result<()>
    where
        E: AbstractEnclave + Send + Sync,
    {
        let envelope = enclave.seal(&Envelope::from(response), recipient);
        self.send_envelope(&envelope).await
    }
}
