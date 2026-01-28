use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bc_components::{EncapsulationPublicKey, SigningPublicKey, ARID, XID};

use super::{encrypt, Event, Nack, QlError, QlPayload, QlPeer, QlPlatform, RequestResponse};
use crate::{executor::ExecutorResponse, ExecutorHandle, MessageKind, QlCodec, RequestConfig};

#[derive(Clone)]
pub struct QlExecutorHandle<P>
where
    P: QlPlatform,
{
    handle: ExecutorHandle,
    platform: Arc<P>,
}

pub struct Response<T, P>
where
    P: QlPlatform,
{
    inner: ResponseInner<P>,
    _type: PhantomData<fn() -> T>,
}

enum ResponseInner<P>
where
    P: QlPlatform,
{
    Err(Option<QlError>),
    Ok {
        response: ExecutorResponse,
        platform: Arc<P>,
    },
}

impl<T, P> Future for Response<T, P>
where
    T: QlCodec,
    P: QlPlatform,
{
    type Output = Result<T, QlError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.inner {
            ResponseInner::Err(e) => {
                let e = e.take();
                let e = e.unwrap_or(QlError::Send(crate::ExecutorError::Cancelled));
                Poll::Ready(Err(e))
            }
            ResponseInner::Ok { response, platform } => {
                Pin::new(response).poll(cx).map(|response| {
                    let response = response?;
                    encrypt::verify_header(platform.as_ref(), &response.header)?;
                    let peer = platform.lookup_peer_or_fail(response.header.sender)?;
                    let session_key = encrypt::session_key_for_header(
                        platform.as_ref(),
                        &peer,
                        &response.header,
                    )?;
                    let decrypted = platform.decrypt_message(
                        &session_key,
                        &response.header.aad_data(),
                        &response.payload,
                    )?;
                    peer.set_pending_handshake(None);
                    if response.header.kind == MessageKind::Nack {
                        let nack = Nack::from(decrypted);
                        return Err(QlError::Nack(nack));
                    }
                    if response.header.kind != MessageKind::Response {
                        return Err(QlError::InvalidPayload);
                    }
                    let message = T::try_from(decrypted)?;
                    Ok(message)
                })
            }
        }
    }
}

impl<P> QlExecutorHandle<P>
where
    P: QlPlatform,
{
    pub fn new(handle: ExecutorHandle, platform: Arc<P>) -> Self {
        Self { handle, platform }
    }

    pub fn request<M>(
        &self,
        message: M,
        recipient: XID,
        request_config: RequestConfig,
    ) -> Response<M::Response, P>
    where
        M: RequestResponse,
    {
        let platform = self.platform.clone();
        let payload = QlPayload {
            message_id: M::ID,
            payload: message.into(),
        };
        let message_id = ARID::new();
        let inner = match encrypt::encrypt_payload_for_recipient(
            platform.as_ref(),
            recipient,
            MessageKind::Request,
            message_id,
            payload.into(),
        ) {
            Ok((header, encrypted)) => {
                let response = self.handle.request(header, encrypted, request_config);

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
    ) -> Result<(), QlError>
    where
        M: Event,
    {
        let payload = QlPayload {
            message_id: M::ID,
            payload: message.into(),
        };
        let message_id = ARID::new();
        let (header, encrypted) = encrypt::encrypt_payload_for_recipient(
            self.platform.as_ref(),
            recipient,
            MessageKind::Event,
            message_id,
            payload.into(),
        )?;
        self.handle.send_event(header, encrypted);
        Ok(())
    }

    pub fn send_pairing_request(
        &self,
        recipient_signing_key: &SigningPublicKey,
        recipient_encapsulation_key: &EncapsulationPublicKey,
    ) -> Result<(), QlError> {
        let (header, encrypted) = encrypt::encrypt_pairing_request(
            self.platform.as_ref(),
            recipient_signing_key,
            recipient_encapsulation_key,
        )?;
        self.handle.send_message(header, encrypted);
        Ok(())
    }
}
