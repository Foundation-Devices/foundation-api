use crate::{
    read_bytes, ChunkQueue, Error, FramedPrefixStep, FramedReadStep, FramedReader, RouterConfig,
    RpcCodec, RpcError, RpcRead,
};

/// reads one length-delimited value and rejects trailing bytes
pub(crate) async fn read_framed_request<T, R>(
    reader: &mut R,
    config: RouterConfig,
) -> Result<T, RpcError<T::Error, R::Error>>
where
    T: RpcCodec,
    R: RpcRead,
{
    let mut value_reader = FramedReader::<T>::default();
    let mut total_read = 0usize;

    let value = loop {
        match value_reader.advance::<R::Error>() {
            Ok(FramedReadStep::Value(value)) => break value,
            Ok(FramedReadStep::NeedMore(next)) => value_reader = next,
            Err(error) => return Err(error),
        }

        let remaining = config.max_request_bytes.saturating_sub(total_read);
        if remaining == 0 {
            return Err(RpcError::Protocol(Error::LengthOverflow));
        }

        match read_bytes(reader, remaining).await {
            Ok(Some(chunk)) => {
                total_read += chunk.len();
                value_reader = value_reader.push(chunk);
            }
            Ok(None) => return Err(RpcError::Protocol(Error::Truncated)),
            Err(error) => return Err(RpcError::Transport(error)),
        }
    };

    let remaining = config.max_request_bytes.saturating_sub(total_read);
    let probe = remaining.max(1);
    match read_bytes(reader, probe).await {
        Ok(None) => Ok(value),
        Ok(Some(_)) if remaining == 0 => Err(RpcError::Protocol(Error::LengthOverflow)),
        Ok(Some(_)) => Err(RpcError::Protocol(Error::TrailingBytes)),
        Err(error) => Err(RpcError::Transport(error)),
    }
}

/// reads one length-delimited value and returns any bytes already buffered
pub(crate) async fn read_framed_request_prefix<T, R>(
    reader: &mut R,
    config: RouterConfig,
) -> Result<(T, ChunkQueue), RpcError<T::Error, R::Error>>
where
    T: RpcCodec,
    R: RpcRead,
{
    let mut value_reader = FramedReader::<T>::default();
    let mut total_read = 0usize;

    loop {
        match value_reader.advance_prefix::<R::Error>() {
            Ok(FramedPrefixStep::Value { value, bytes }) => return Ok((value, bytes)),
            Ok(FramedPrefixStep::NeedMore(next)) => value_reader = next,
            Err(error) => return Err(error),
        }

        let remaining = config.max_request_bytes.saturating_sub(total_read);
        if remaining == 0 {
            return Err(RpcError::Protocol(Error::LengthOverflow));
        }

        match read_bytes(reader, remaining).await {
            Ok(Some(chunk)) => {
                total_read += chunk.len();
                value_reader = value_reader.push(chunk);
            }
            Ok(None) => return Err(RpcError::Protocol(Error::Truncated)),
            Err(error) => return Err(RpcError::Transport(error)),
        }
    }
}

/// reads one eof-delimited value up to the configured request limit
pub(crate) async fn read_eof_request<T, R>(
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
        let probe = remaining.max(1);
        match read_bytes(reader, probe).await {
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
