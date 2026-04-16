use crate::{
    read_bytes, CallError, ChunkQueue, FramedValueReader, ReadValueStep, RouterConfig, RpcCodec, RpcRead,
    StreamCloseCode,
};

pub mod download;
pub mod notification;
pub mod request;
pub mod request_with_progress;
pub mod subscription;
pub mod upload;

pub use download::Download;
pub use notification::Notification;
pub use request::Request;
pub use request_with_progress::RequestWithProgress;
pub use subscription::Subscription;
pub use upload::Upload;

/// reads one length-delimited value and rejects trailing bytes
async fn read_framed_value<T, R>(
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
            Err(crate::CodecError::Rpc(_error)) => return Err(StreamCloseCode::REFUSED.into()),
            Err(crate::CodecError::Codec(_error)) => return Err(StreamCloseCode::REFUSED.into()),
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

/// reads one eof-delimited value and rejects trailing bytes
async fn read_whole_value<T, R>(reader: &mut R) -> Result<T, CallError<T::Error, R::Error>>
where
    T: RpcCodec,
    R: RpcRead,
{
    let mut bytes = ChunkQueue::default();

    while let Some(chunk) = read_bytes(reader, usize::MAX)
        .await
        .map_err(CallError::Transport)?
    {
        bytes.push(chunk);
    }

    let value = T::decode_value(&mut bytes).map_err(CallError::Codec)?;
    if bytes.remaining() > 0 {
        return Err(crate::Error::TrailingBytes.into());
    }
    Ok(value)
}
