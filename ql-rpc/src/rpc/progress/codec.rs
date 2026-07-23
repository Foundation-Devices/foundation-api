use std::marker::PhantomData;

use bytes::Bytes;

use crate::{progress::Progress, ChunkQueue, Error, RpcCodec, RpcError};

pub enum ReadStep<M: Progress> {
    NeedMore,
    Progress(M::Progress),
    Response(M::Response),
}

pub struct ResponseReader<M: Progress> {
    bytes: ChunkQueue,
    marker: PhantomData<fn() -> M>,
}

impl<M: Progress> Default for ResponseReader<M> {
    fn default() -> Self {
        Self {
            bytes: ChunkQueue::default(),
            marker: PhantomData,
        }
    }
}

impl<M: Progress> ResponseReader<M> {
    pub fn push(&mut self, chunk: Bytes) {
        self.bytes.push(chunk);
    }

    pub fn advance<E>(&mut self) -> Result<ReadStep<M>, RpcError<M::Error, E>> {
        let Some((kind, mut body)) = self
            .bytes
            .try_take_tagged_part()
            .map_err(RpcError::Protocol)?
        else {
            return Ok(ReadStep::NeedMore);
        };

        match kind {
            x if x == FrameKind::Progress as u8 => {
                let value = {
                    let value = M::Progress::decode_value(&mut body).map_err(RpcError::Codec)?;
                    drop(body);
                    value
                };
                Ok(ReadStep::Progress(value))
            }
            x if x == FrameKind::Response as u8 => {
                let response = M::Response::decode_value(&mut body).map_err(RpcError::Codec)?;
                drop(body);
                if self.bytes.remaining() > 0 {
                    Err(RpcError::Protocol(Error::TrailingBytes))
                } else {
                    Ok(ReadStep::Response(response))
                }
            }
            other => Err(RpcError::Protocol(Error::UnexpectedFrameKind(other))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Progress = 1,
    Response = 2,
}
