use bytes::Bytes;

use crate::{
    codec, read_bytes, write_bytes, ChunkQueue, Error, RouterConfig, RpcCodec, RpcError, RpcRead,
    RpcWrite,
};

pub async fn write_eof_value<T, W>(mut writer: W, value: &T) -> Result<(), W::Error>
where
    T: RpcCodec,
    W: RpcWrite,
{
    let mut encoded = Vec::new();
    value.encode_value(&mut encoded);
    write_bytes(&mut writer, Bytes::from(encoded)).await?;
    writer.finish().await
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
