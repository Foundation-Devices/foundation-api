use std::marker::PhantomData;

use bytes::Bytes;

use crate::{subscription::Subscription, ChunkQueue, RpcCodec, RpcError};

pub enum ReadStep<M: Subscription> {
    NeedMore,
    Item(M::Event),
}

pub struct ResponseReader<M: Subscription> {
    bytes: ChunkQueue,
    marker: PhantomData<fn() -> M>,
}

impl<M: Subscription> Default for ResponseReader<M> {
    fn default() -> Self {
        Self {
            bytes: ChunkQueue::default(),
            marker: PhantomData,
        }
    }
}

impl<M: Subscription> ResponseReader<M> {
    pub fn push(&mut self, chunk: Bytes) {
        self.bytes.push(chunk);
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.remaining() == 0
    }

    pub fn advance<E>(&mut self) -> Result<ReadStep<M>, RpcError<M::Error, E>> {
        let Some(mut body) = self.bytes.try_take_part().map_err(RpcError::Protocol)? else {
            return Ok(ReadStep::NeedMore);
        };

        let item = {
            let item = M::Event::decode_value(&mut body).map_err(RpcError::Codec)?;
            drop(body);
            item
        };
        Ok(ReadStep::Item(item))
    }
}
