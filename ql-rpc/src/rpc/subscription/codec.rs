use std::marker::PhantomData;

use bytes::{BufMut, Bytes};

use crate::{codec, subscription::Subscription, RpcCodec, RpcError};

pub fn encode_request<M: Subscription>(
    request: &M::Request,
    out: &mut (impl BufMut + AsMut<[u8]>),
) {
    request.encode_value(out)
}

pub fn encode_item<M: Subscription>(item: &M::Event, out: &mut (impl BufMut + AsMut<[u8]>)) {
    codec::encode_value_part(item, out)
}

pub enum ReadStep<M: Subscription> {
    NeedMore,
    Item(M::Event),
}

pub struct ResponseReader<M: Subscription> {
    bytes: codec::ChunkQueue,
    marker: PhantomData<fn() -> M>,
}

impl<M: Subscription> Default for ResponseReader<M> {
    fn default() -> Self {
        Self {
            bytes: codec::ChunkQueue::default(),
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
