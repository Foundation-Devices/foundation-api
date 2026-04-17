use crate::{
    read_bytes, ChunkQueue, CodecError, FramedValueReader, ReadValueStep, RouterConfig, RpcCodec,
    RpcRead, StreamCloseCode,
};

/// reads one length-delimited value and rejects trailing bytes
pub(crate) async fn read_framed_request<T, R>(
    reader: &mut R,
    config: RouterConfig,
) -> Result<T, R::Error>
where
    T: RpcCodec,
    R: RpcRead,
{
    let mut value_reader = FramedValueReader::<T>::default();
    let mut total_read = 0usize;

    let value = loop {
        match value_reader.advance() {
            Ok(ReadValueStep::Value(value)) => break value,
            Ok(ReadValueStep::NeedMore(next)) => value_reader = next,
            Err(CodecError::Rpc(_error)) => return Err(StreamCloseCode::REFUSED.into()),
            Err(CodecError::Codec(_error)) => return Err(StreamCloseCode::REFUSED.into()),
        }

        let remaining = config.max_request_bytes.saturating_sub(total_read);
        if remaining == 0 {
            return Err(StreamCloseCode::LIMIT.into());
        }

        match read_bytes(reader, remaining).await {
            Ok(Some(chunk)) => {
                total_read += chunk.len();
                value_reader = value_reader.push(chunk);
            }
            Ok(None) => return Err(StreamCloseCode::REFUSED.into()),
            Err(error) => return Err(error),
        }
    };

    let remaining = config.max_request_bytes.saturating_sub(total_read);
    let probe = remaining.max(1);
    match read_bytes(reader, probe).await {
        Ok(None) => Ok(value),
        Ok(Some(_)) if remaining == 0 => Err(StreamCloseCode::LIMIT.into()),
        Ok(Some(_)) => Err(StreamCloseCode::REFUSED.into()),
        Err(error) => Err(error),
    }
}

/// reads one eof-delimited value up to the configured request limit
pub(crate) async fn read_eof_request<T, R>(reader: &mut R, config: RouterConfig) -> Result<T, R::Error>
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
                    return Err(StreamCloseCode::LIMIT.into());
                }
                total_read += chunk.len();
                bytes.push(chunk);
            }
            Ok(None) => break,
            Err(error) => return Err(error),
        }
    }

    let value = T::decode_value(&mut bytes).map_err(|_error| StreamCloseCode::REFUSED)?;
    if bytes.remaining() > 0 {
        return Err(StreamCloseCode::REFUSED.into());
    }
    Ok(value)
}
