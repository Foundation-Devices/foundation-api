use bytes::Bytes;

use crate::{
    finish_bytes, read_bytes, write_bytes, ChunkQueue, Error, RouterConfig, RpcCodec, RpcError,
    RpcRead, RpcWrite,
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

    while let Some(chunk) = read_bytes(reader).await.map_err(RpcError::Transport)? {
        bytes.push(chunk);
    }

    let value = T::decode_value(&mut bytes).map_err(RpcError::Codec)?;
    if bytes.remaining() > 0 {
        return Err(RpcError::Protocol(Error::TrailingBytes));
    }
    Ok(value)
}

/// reads one length-delimited value and rejects trailing bytes
pub async fn read_framed_request<T, R>(
    reader: &mut R,
    config: RouterConfig,
) -> Result<T, RpcError<T::Error, R::Error>>
where
    T: RpcCodec,
    R: RpcRead,
{
    let (value, buffered) = read_framed_prefix(reader, Some(config.max_request_bytes)).await?;
    buffered.expect_empty().map_err(RpcError::Protocol)?;

    match read_bytes(reader).await {
        Ok(None) => Ok(value),
        Ok(Some(_)) => Err(RpcError::Protocol(Error::TrailingBytes)),
        Err(error) => Err(RpcError::Transport(error)),
    }
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
        if let Some(value) = try_take_framed_value(&mut bytes)? {
            return Ok((value, bytes));
        }

        match read_bytes(reader).await {
            Ok(Some(chunk)) => {
                bytes.push(chunk);
                if let Some(max_len) = max_len {
                    reject_oversized_frame(&bytes, max_len).map_err(RpcError::Protocol)?;
                }
            }
            Ok(None) => return Err(RpcError::Protocol(Error::Truncated)),
            Err(error) => return Err(RpcError::Transport(error)),
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
        match read_bytes(reader).await {
            Ok(Some(chunk)) => {
                if chunk.len() > remaining {
                    return Err(RpcError::Protocol(Error::LengthOverflow));
                }
                total_read += chunk.len();
                bytes.push(chunk);
            }
            Ok(None) => break,
            Err(error) => return Err(RpcError::Transport(error)),
        }
    }

    let value = T::decode_value(&mut bytes).map_err(RpcError::Codec)?;
    if bytes.remaining() > 0 {
        return Err(RpcError::Protocol(Error::TrailingBytes));
    }
    Ok(value)
}

fn try_take_framed_value<T, E>(bytes: &mut ChunkQueue) -> Result<Option<T>, RpcError<T::Error, E>>
where
    T: RpcCodec,
{
    let Some(mut body) = bytes.try_take_part().map_err(RpcError::Protocol)? else {
        return Ok(None);
    };

    let value = T::decode_value(&mut body).map_err(RpcError::Codec)?;
    Ok(Some(value))
}

fn reject_oversized_frame(bytes: &ChunkQueue, max_len: usize) -> Result<(), Error> {
    let oversized = match bytes.next_part_total_len()? {
        Some(len) => len > max_len,
        None => bytes.remaining() > max_len,
    };

    if oversized {
        return Err(Error::LengthOverflow);
    }
    Ok(())
}
