use std::marker::PhantomData;

use bytes::{Buf, BufMut, Bytes};

use crate::{codec, MethodId, ReadValueStep, RpcCodec, RpcCodecError, RpcError, ValueReader};

pub trait Subscription {
    const METHOD: MethodId;
    type Error;
    type Request: RpcCodec<Error = Self::Error>;
    type Event: RpcCodec<Error = Self::Error>;
}

pub type RequestReader<M> = ValueReader<<M as Subscription>::Request>;
pub type RequestReadStep<M> = ReadValueStep<<M as Subscription>::Request>;

pub enum ReadStep<M: Subscription> {
    NeedMore(ResponseReader<M>),
    Item {
        value: M::Event,
        next: ResponseReader<M>,
    },
    End,
}

pub struct ResponseReader<M: Subscription> {
    bytes: codec::ChunkQueue,
    marker: PhantomData<fn() -> M>,
}

impl<M: Subscription> Default for ResponseReader<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: Subscription> ResponseReader<M> {
    pub fn new() -> Self {
        Self {
            bytes: codec::ChunkQueue::new(),
            marker: PhantomData,
        }
    }

    pub fn push(mut self, chunk: Bytes) -> Self {
        self.bytes.push(chunk);
        self
    }

    pub fn advance(self) -> Result<ReadStep<M>, RpcCodecError<M::Error>> {
        let mut this = self;
        let Some(mut body) = this.bytes.try_take_part().map_err(RpcCodecError::Rpc)? else {
            return Ok(ReadStep::NeedMore(this));
        };

        if body.remaining() == 0 {
            drop(body);
            if this.bytes.remaining() == 0 {
                return Ok(ReadStep::End);
            }
            return Err(RpcCodecError::Rpc(RpcError::TrailingBytes));
        }

        let item = {
            let item = M::Event::decode_value(&mut body).map_err(RpcCodecError::Codec)?;
            drop(body);
            item
        };
        Ok(ReadStep::Item {
            value: item,
            next: this,
        })
    }
}

pub fn encode_request<M: Subscription>(
    request: &M::Request,
    out: &mut (impl BufMut + AsMut<[u8]>),
) -> Result<(), M::Error> {
    codec::encode_value_part(request, out)
}

pub fn encode_item<M: Subscription>(
    item: &M::Event,
    out: &mut (impl BufMut + AsMut<[u8]>),
) -> Result<(), <M::Event as RpcCodec>::Error> {
    codec::encode_value_part(item, out)
}

pub fn encode_end(out: &mut impl BufMut) {
    codec::push_length(out, 0);
}

#[cfg(test)]
mod tests {
    use bytes::{Buf, BufMut, Bytes};

    use super::{encode_end, encode_item, ReadStep, ResponseReader, Subscription};
    use crate::{MethodId, RpcCodec};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct BytesValue(Vec<u8>);

    impl RpcCodec for BytesValue {
        type Error = core::convert::Infallible;

        fn encode_value<B: BufMut + ?Sized>(&self, out: &mut B) -> Result<(), Self::Error> {
            out.put_slice(&self.0);
            Ok(())
        }

        fn decode_value<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error> {
            Ok(Self(bytes.copy_to_bytes(bytes.remaining()).to_vec()))
        }
    }

    struct Feed;

    impl Subscription for Feed {
        const METHOD: MethodId = MethodId(17);
        type Error = core::convert::Infallible;
        type Request = BytesValue;
        type Event = BytesValue;
    }

    #[test]
    fn response_reader_streams_items_until_end() {
        let mut encoded = Vec::new();
        encode_item::<Feed>(&BytesValue(b"one".to_vec()), &mut encoded).unwrap();
        encode_item::<Feed>(&BytesValue(b"two".to_vec()), &mut encoded).unwrap();
        encode_end(&mut encoded);

        let reader = match ResponseReader::<Feed>::new()
            .push(Bytes::from(encoded))
            .advance()
            .unwrap()
        {
            ReadStep::Item { value, next } => {
                assert_eq!(value, BytesValue(b"one".to_vec()));
                next
            }
            _ => unreachable!(),
        };

        let reader = match reader.advance().unwrap() {
            ReadStep::Item { value, next } => {
                assert_eq!(value, BytesValue(b"two".to_vec()));
                next
            }
            _ => unreachable!(),
        };

        assert!(matches!(reader.advance().unwrap(), ReadStep::End));
    }
}
