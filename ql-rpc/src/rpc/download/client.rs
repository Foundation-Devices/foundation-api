use std::marker::PhantomData;

use ql_common::ResetCode;

use crate::{
    download::Download,
    rpc::{read_framed_prefix, write_eof_value},
    MultipartReader, RpcError, RpcRead, RpcStream,
};

pub async fn start<M, St>(
    stream: St,
    request: &M::Request,
) -> Result<DownloadCall<M, St::Reader>, RpcError<M::Error, St::Error>>
where
    M: Download,
    St: RpcStream,
{
    let (reader, writer) = stream.split();
    write_eof_value(writer, request)
        .await
        .map_err(RpcError::Transport)?;
    Ok(DownloadCall::new(reader))
}

pub struct DownloadCall<M, R>
where
    M: Download,
    R: RpcRead,
{
    stream: R,
    marker: PhantomData<fn() -> M>,
}

impl<M, R> DownloadCall<M, R>
where
    M: Download,
    R: RpcRead,
{
    pub fn new(stream: R) -> Self {
        Self {
            stream,
            marker: PhantomData,
        }
    }

    pub async fn start(
        mut self,
    ) -> Result<(M::ResponseHeader, MultipartReader<M::PartHeader, R>), RpcError<M::Error, R::Error>>
    {
        let (value, bytes) = read_framed_prefix::<M::ResponseHeader, _>(&mut self.stream, None)
            .await
            .inspect_err(|error| {
                self.stream
                    .reset(error.reset_code().unwrap_or(ResetCode::DROPPED));
            })?;
        Ok((value, MultipartReader::new(self.stream, bytes)))
    }

    pub fn reset(mut self, code: ResetCode) {
        self.stream.reset(code);
    }
}
