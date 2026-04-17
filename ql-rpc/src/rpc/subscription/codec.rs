use std::marker::PhantomData;

use bytes::{BufMut, Bytes};

use crate::{codec, subscription::Subscription, CodecError, RpcCodec};

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
    NeedMore(ResponseReader<M>),
    Item {
        value: M::Event,
        next: ResponseReader<M>,
    },
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
    pub fn push(mut self, chunk: Bytes) -> Self {
        self.bytes.push(chunk);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.remaining() == 0
    }

    pub fn advance(self) -> Result<ReadStep<M>, CodecError<M::Error>> {
        let mut this = self;
        let Some(mut body) = this.bytes.try_take_part()? else {
            return Ok(ReadStep::NeedMore(this));
        };

        let item = {
            let item = M::Event::decode_value(&mut body).map_err(CodecError::Codec)?;
            drop(body);
            item
        };
        Ok(ReadStep::Item {
            value: item,
            next: this,
        })
    }
}
