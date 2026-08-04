use bytes::Bytes;

use crate::{
    codec, finish_bytes, read_bytes, write_bytes, ChunkQueue, Error, RouterConfig, RpcCodec,
    RpcError, RpcRead, RpcWrite,
};

pub async fn write_eof_value<T, W>(writer: &mut W, value: &T) -> Result<(), W::Error>
where
    T: RpcCodec,
    W: RpcWrite,
{
    let mut encoded = Vec::new();
    value.encode_value(&mut encoded);
    write_bytes(writer, Bytes::from(encoded)).await?;
    finish_bytes(writer).await
}

pub async fn read_eof_value<T, R>(reader: &mut R) -> Result<T, RpcError<T::Error, R::Error>>
where
    T: RpcCodec,
    R: RpcRead,
{
    let mut bytes = ChunkQueue::default();

    loop {
        let chunk = read_bytes(reader).await.map_err(RpcError::Transport)?;
        if chunk.is_empty() {
            break;
        }
        bytes.push(chunk);
    }

    codec::decode_exact(&mut bytes)
}

pub async fn read_framed_prefix<T, R>(
    reader: &mut R,
    max_len: Option<usize>,
) -> Result<(T, ChunkQueue), RpcError<T::Error, R::Error>>
where
    T: RpcCodec,
    R: RpcRead,
{
    let mut bytes = ChunkQueue::default();

    loop {
        let value = match bytes.try_take_part().map_err(RpcError::Protocol)? {
            Some(mut body) => Some(codec::decode_exact(&mut body)?),
            None => None,
        };
        if let Some(value) = value {
            return Ok((value, bytes));
        }

        let chunk = read_bytes(reader).await.map_err(RpcError::Transport)?;
        if chunk.is_empty() {
            return Err(Error::Truncated.into());
        }
        bytes.push(chunk);
        if let Some(max_len) = max_len {
            if bytes.next_part_len()?.is_some_and(|len| len > max_len) {
                return Err(Error::LengthOverflow.into());
            }
        }
    }
}

/// reads one eof-delimited value up to the configured request limit
pub async fn read_eof_request<T, R>(
    reader: &mut R,
    config: RouterConfig,
) -> Result<T, RpcError<T::Error, R::Error>>
where
    T: RpcCodec,
    R: RpcRead,
{
    let mut bytes = ChunkQueue::default();
    let mut total_read = 0usize;

    loop {
        let remaining = config.max_request_bytes.saturating_sub(total_read);
        let chunk = read_bytes(reader).await.map_err(RpcError::Transport)?;
        if chunk.is_empty() {
            break;
        }
        if chunk.len() > remaining {
            return Err(Error::LengthOverflow.into());
        }
        total_read += chunk.len();
        bytes.push(chunk);
    }

    codec::decode_exact(&mut bytes)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        convert::Infallible,
        future::Future,
        task::{Context, Poll, Waker},
    };

    use bytes::Bytes;
    use ql_common::ResetCode;

    use super::read_framed_prefix;
    use crate::{codec, Error, RpcError, RpcRead};

    struct Reader(VecDeque<Bytes>);

    impl RpcRead for Reader {
        type Error = Infallible;

        fn poll_read(&mut self, _cx: &mut Context<'_>) -> Poll<Result<Bytes, Self::Error>> {
            Poll::Ready(Ok(self.0.pop_front().unwrap_or_default()))
        }

        fn reset(&mut self, _code: ResetCode) {}
    }

    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut cx = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("future unexpectedly pending"),
        }
    }

    #[test]
    fn framed_prefix_limit_counts_payload_bytes() {
        let value = vec![1, 2, 3, 4];
        let mut encoded = Vec::new();
        codec::encode_value_part(&value, &mut encoded);
        let mut reader = Reader(VecDeque::from([Bytes::from(encoded)]));
        let (decoded, _) = ready(read_framed_prefix::<Vec<u8>, _>(&mut reader, Some(4))).unwrap();
        assert_eq!(decoded, value);

        let mut reader = Reader(VecDeque::from([Bytes::copy_from_slice(
            &11_u64.to_le_bytes(),
        )]));
        assert!(matches!(
            ready(read_framed_prefix::<Vec<u8>, _>(&mut reader, Some(10))),
            Err(RpcError::Protocol(Error::LengthOverflow))
        ));
    }
}
