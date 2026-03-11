use dcbor::CBOR;

use super::{modality::RequestResponse, RpcError, RpcRequestHead, RpcResponseHead};
use crate::runtime::{RuntimeHandle, StreamConfig};

#[derive(Clone)]
pub struct RpcHandle {
    inner: RuntimeHandle,
}

impl RpcHandle {
    pub fn new(inner: RuntimeHandle) -> Self {
        Self { inner }
    }

    pub fn runtime(&self) -> &RuntimeHandle {
        &self.inner
    }

    pub async fn request<M: RequestResponse>(
        &self,
        request: M,
        config: StreamConfig,
    ) -> Result<M::Response, RpcError> {
        let request_body = Into::<CBOR>::into(request).to_cbor_data();
        let request_head = CBOR::from(RpcRequestHead::new(
            M::METHOD,
            Some(request_body.len() as u64),
        ))
        .to_cbor_data();

        let crate::runtime::PendingStream {
            mut request,
            accepted,
        } = self.inner.open_stream(request_head, config).await?;
        let accepted = accepted.await?;
        request.write_all(&request_body).await?;
        request.finish().await?;

        let response_head =
            RpcResponseHead::try_from(CBOR::try_from_data(&accepted.response_head)?)?;
        if response_head.version != super::RPC_VERSION {
            return Err(RpcError::BadVersion(response_head.version));
        }

        let response_body =
            read_stream_to_end(accepted.response, response_head.content_length).await?;
        Ok(CBOR::try_from_data(&response_body)?.try_into()?)
    }
}

async fn read_stream_to_end(
    mut stream: crate::runtime::InboundByteStream,
    content_length: Option<u64>,
) -> Result<Vec<u8>, RpcError> {
    let mut body = match content_length.and_then(|length| usize::try_from(length).ok()) {
        Some(length) => Vec::with_capacity(length),
        None => Vec::new(),
    };
    while let Some(chunk) = stream.next_chunk().await? {
        body.extend_from_slice(&chunk);
    }
    if let Some(expected) = content_length {
        let actual = body.len() as u64;
        if actual != expected {
            return Err(RpcError::ContentLengthMismatch { expected, actual });
        }
    }
    Ok(body)
}
