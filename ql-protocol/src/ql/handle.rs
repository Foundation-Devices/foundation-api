use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bc_components::{EncapsulationCiphertext, ARID, XID};

use super::{Event, QlPayload, QlPlatform, RequestResponse, RouterError};
use crate::{
    executor::ExecutorResponse, EncodeQlConfig, ExecutorHandle, MessageKind, QlCodec, QlHeader,
    RequestConfig,
};

#[derive(Clone)]
pub struct QlExecutorHandle {
    handle: ExecutorHandle,
    platform: Arc<dyn QlPlatform>,
}

pub struct Response<T> {
    inner: ResponseInner,
    _type: PhantomData<fn() -> T>,
}

enum ResponseInner {
    Err(Option<RouterError>),
    Ok {
        response: ExecutorResponse,
        platform: Arc<dyn QlPlatform>,
    },
}

impl<T> Future for Response<T>
where
    T: QlCodec,
{
    type Output = Result<T, RouterError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.inner {
            ResponseInner::Err(e) => {
                let e = e.take();
                let e = e.unwrap_or(RouterError::Send(crate::QlError::Cancelled));
                Poll::Ready(Err(e))
            }
            ResponseInner::Ok { response, platform } => {
                Pin::new(response).poll(cx).map(|response| {
                    let response = response?;
                    let session_key = platform
                        .session_for_peer(response.header.sender)
                        .ok_or(RouterError::MissingSession(response.header.sender))?;
                    let decrypted = platform.decrypt_message(
                        &session_key,
                        &response.header.aad_data(),
                        &response.payload,
                    )?;
                    let message = T::try_from(decrypted)?;
                    Ok(message)
                })
            }
        }
    }
}

impl QlExecutorHandle {
    pub fn new(handle: ExecutorHandle, platform: Arc<dyn QlPlatform>) -> Self {
        Self { handle, platform }
    }

    pub fn request<M>(
        &self,
        message: M,
        recipient: XID,
        request_config: RequestConfig,
    ) -> Response<M::Response>
    where
        M: RequestResponse,
    {
        let platform = self.platform.clone();
        let payload = QlPayload {
            message_id: M::ID,
            payload: message.into(),
        };
        let message_id = ARID::new();
        let inner = match self.encrypt_payload_for_recipient(
            recipient,
            MessageKind::Request,
            message_id,
            payload.into(),
        ) {
            Ok((encrypted, config)) => {
                let response = self.handle.request(
                    message_id,
                    encrypted,
                    config,
                    request_config,
                    platform.signer(),
                );

                ResponseInner::Ok {
                    response,
                    platform: self.platform.clone(),
                }
            }
            Err(e) => ResponseInner::Err(Some(e)),
        };
        Response {
            inner,
            _type: Default::default(),
        }
    }

    pub fn send_event<M>(
        &self,
        message: M,
        recipient: XID,
        _valid_for: Duration,
    ) -> Result<(), RouterError>
    where
        M: Event,
    {
        let payload = QlPayload {
            message_id: M::ID,
            payload: message.into(),
        };
        let message_id = ARID::new();
        let (encrypted, config) = self.encrypt_payload_for_recipient(
            recipient,
            MessageKind::Event,
            message_id,
            payload.into(),
        )?;
        self.handle
            .send_event(message_id, encrypted, config, self.platform.signer());
        Ok(())
    }

    fn encrypt_payload_for_recipient(
        &self,
        recipient: XID,
        kind: MessageKind,
        message_id: ARID,
        payload: dcbor::CBOR,
    ) -> Result<(bc_components::EncryptedMessage, EncodeQlConfig), RouterError> {
        let platform = self.platform.as_ref();
        let (session_key, kem_ct, sign_header) = match platform.session_for_peer(recipient) {
            Some(session_key) => (session_key, None, false),
            None => self.create_session(recipient)?,
        };
        let valid_until = now_secs().saturating_add(platform.message_expiration().as_secs());
        let header_unsigned = QlHeader {
            kind,
            id: message_id,
            sender: platform.sender_xid(),
            recipient,
            valid_until,
            kem_ct: kem_ct.clone(),
            signature: None,
        };
        let aad = header_unsigned.aad_data();
        let payload_bytes = payload.to_cbor_data();
        let encrypted = session_key.encrypt(payload_bytes, Some(aad), None::<bc_components::Nonce>);
        let config = EncodeQlConfig {
            sender: platform.sender_xid(),
            recipient,
            valid_until,
            kem_ct,
            sign_header,
        };
        Ok((encrypted, config))
    }

    fn create_session(
        &self,
        recipient: XID,
    ) -> Result<
        (
            bc_components::SymmetricKey,
            Option<EncapsulationCiphertext>,
            bool,
        ),
        RouterError,
    > {
        let platform = self.platform.as_ref();
        let recipient_key = platform
            .lookup_recipient(recipient)
            .ok_or(RouterError::UnknownRecipient(recipient))?;
        let (session_key, kem_ct) = recipient_key.encapsulate_new_shared_secret();
        platform.store_session(recipient, session_key.clone());
        Ok((session_key, Some(kem_ct), true))
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
