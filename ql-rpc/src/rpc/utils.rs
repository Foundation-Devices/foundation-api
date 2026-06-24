use bytes::Bytes;

use crate::{
    finish_bytes, read_bytes, write_bytes, ChunkQueue, Error, FramedPrefixStep, FramedReadStep,
    FramedReader, RouterConfig, RpcCodec, RpcError, RpcRead, RpcWrite,
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
    let mut value_reader = FramedReader::<T>::default();
    let value = loop {
        match value_reader.advance::<R::Error>() {
            Ok(FramedReadStep::Value(value)) => break value,
            Ok(FramedReadStep::NeedMore(next)) => value_reader = next,
            Err(error) => return Err(error),
        }

        match read_bytes(reader).await {
            Ok(Some(chunk)) => {
                value_reader = value_reader.push(chunk);
                reject_oversized_frame(&value_reader, config)?;
            }
            Ok(None) => return Err(RpcError::Protocol(Error::Truncated)),
            Err(error) => return Err(RpcError::Transport(error)),
        }
    };

    match read_bytes(reader).await {
        Ok(None) => Ok(value),
        Ok(Some(_)) => Err(RpcError::Protocol(Error::TrailingBytes)),
        Err(error) => Err(RpcError::Transport(error)),
    }
}

/// reads one length-delimited value and returns any bytes already buffered
pub async fn read_framed_request_prefix<T, R>(
    reader: &mut R,
    config: RouterConfig,
) -> Result<(T, ChunkQueue), RpcError<T::Error, R::Error>>
where
    T: RpcCodec,
    R: RpcRead,
{
    let mut value_reader = FramedReader::<T>::default();
    loop {
        match value_reader.advance_prefix::<R::Error>() {
            Ok(FramedPrefixStep::Value { value, bytes }) => return Ok((value, bytes)),
            Ok(FramedPrefixStep::NeedMore(next)) => value_reader = next,
            Err(error) => return Err(error),
        }

        match read_bytes(reader).await {
            Ok(Some(chunk)) => {
                value_reader = value_reader.push(chunk);
                reject_oversized_frame(&value_reader, config)?;
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

fn reject_oversized_frame<T, E>(
    value_reader: &FramedReader<T>,
    config: RouterConfig,
) -> Result<(), RpcError<T::Error, E>>
where
    T: RpcCodec,
{
    if value_reader
        .exceeds_total_len(config.max_request_bytes)
        .map_err(RpcError::Protocol)?
    {
        return Err(RpcError::Protocol(Error::LengthOverflow));
    }
    Ok(())
}
