use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bc_components::XID;

use super::{Event, RequestResponse, RouterError, RouterPlatform, TypedPayload};
use crate::v2::{
    executor::ExecutorResponse, EncodeQlConfig, ExecutorHandle, QlCodec, RequestConfig,
};

#[derive(Clone)]
pub struct TypedExecutorHandle {
    handle: ExecutorHandle,
    platform: Arc<dyn RouterPlatform>,
}

pub struct Response<T> {
    inner: ResponseInner,
    _type: PhantomData<fn() -> T>,
}

enum ResponseInner {
    Err(Option<RouterError>),
    Ok {
        response: ExecutorResponse,
        platform: Arc<dyn RouterPlatform>,
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
                let e = e.unwrap_or(RouterError::Send(crate::v2::QlError::Cancelled));
                Poll::Ready(Err(e))
            }
            ResponseInner::Ok { response, platform } => {
                Pin::new(response).poll(cx).map(|response| {
                    let response = response?;
                    let decrypted = platform.decrypt_payload(response.payload)?;
                    let message = T::try_from(decrypted)?;
                    Ok(message)
                })
            }
        }
    }
}

impl TypedExecutorHandle {
    pub fn new(handle: ExecutorHandle, platform: Arc<dyn RouterPlatform>) -> Self {
        Self { handle, platform }
    }

    pub fn request<M>(
        &self,
        message: M,
        recipient: XID,
        request_config: RequestConfig,
        valid_for: Duration,
    ) -> Response<M::Response>
    where
        M: RequestResponse,
    {
        let platform = self.platform.clone();
        let payload = TypedPayload {
            message_id: M::ID,
            payload: message.into(),
        };
        let inner = match platform.encrypt_payload_or_fail(recipient, payload.into()) {
            Ok(encrypted) => {
                let response = self.handle.request(
                    encrypted,
                    EncodeQlConfig {
                        signing_key: platform.signing_key().clone(),
                        recipient,
                        valid_for,
                    },
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
        valid_for: Duration,
    ) -> Result<(), RouterError>
    where
        M: Event,
    {
        let platform = self.platform.clone();
        let handle = self.handle.clone();
        let payload = TypedPayload {
            message_id: M::ID,
            payload: message.into(),
        };
        let encrypted = platform.encrypt_payload_or_fail(recipient, payload.into())?;
        handle.send_event(
            encrypted,
            EncodeQlConfig {
                signing_key: platform.signing_key().clone(),
                recipient,
                valid_for,
            },
            platform.signer(),
        );
        Ok(())
    }
}
