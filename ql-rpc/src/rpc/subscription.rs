use std::marker::PhantomData;

use bytes::{BufMut, Bytes};

use crate::{CodecError, RouteId, RpcCodec, codec};

pub trait Subscription {
    const ROUTE: RouteId;
    type Error;
    type Request: RpcCodec<Error = Self::Error>;
    type Event: RpcCodec<Error = Self::Error>;
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

    pub fn is_empty(&self) -> bool {
        self.bytes.remaining() == 0
    }

    pub fn advance(self) -> Result<ReadStep<M>, CodecError<M::Error>> {
        let mut this = self;
        let Some(mut body) = this.bytes.try_take_part().map_err(CodecError::Rpc)? else {
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

pub fn encode_request<M: Subscription>(
    request: &M::Request,
    out: &mut (impl BufMut + AsMut<[u8]>),
) {
    codec::encode_value_part(request, out)
}

pub fn encode_item<M: Subscription>(item: &M::Event, out: &mut (impl BufMut + AsMut<[u8]>)) {
    codec::encode_value_part(item, out)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{ReadStep, ResponseReader, Subscription, encode_item};
    use crate::RouteId;

    struct Feed;

    impl Subscription for Feed {
        const ROUTE: RouteId = RouteId::from_u32(17);
        type Error = core::convert::Infallible;
        type Request = Vec<u8>;
        type Event = Vec<u8>;
    }

    #[test]
    fn response_reader_streams_items_until_end() {
        let mut encoded = Vec::new();
        encode_item::<Feed>(&b"one".to_vec(), &mut encoded);
        encode_item::<Feed>(&b"two".to_vec(), &mut encoded);

        let reader = match ResponseReader::<Feed>::new()
            .push(Bytes::from(encoded))
            .advance()
            .unwrap()
        {
            ReadStep::Item { value, next } => {
                assert_eq!(value, b"one".to_vec());
                next
            }
            _ => unreachable!(),
        };

        let reader = match reader.advance().unwrap() {
            ReadStep::Item { value, next } => {
                assert_eq!(value, b"two".to_vec());
                next
            }
            _ => unreachable!(),
        };

        match reader.advance().unwrap() {
            ReadStep::NeedMore(next) => assert!(next.is_empty()),
            _ => unreachable!(),
        }
    }

    #[test]
    fn response_reader_waits_for_transport_eof_when_no_end_frame_is_present() {
        let mut encoded = Vec::new();
        encode_item::<Feed>(&b"one".to_vec(), &mut encoded);

        let reader = match ResponseReader::<Feed>::new()
            .push(Bytes::from(encoded))
            .advance()
            .unwrap()
        {
            ReadStep::Item { value, next } => {
                assert_eq!(value, b"one".to_vec());
                next
            }
            _ => unreachable!(),
        };

        match reader.advance().unwrap() {
            ReadStep::NeedMore(next) => assert!(next.is_empty()),
            _ => unreachable!(),
        }
    }

    #[test]
    fn response_reader_allows_empty_event_payloads() {
        let mut encoded = Vec::new();
        encode_item::<Feed>(&Vec::new(), &mut encoded);

        match ResponseReader::<Feed>::new()
            .push(Bytes::from(encoded))
            .advance()
            .unwrap()
        {
            ReadStep::Item { value, next } => {
                assert_eq!(value, Vec::<u8>::new());
                assert!(
                    matches!(next.advance().unwrap(), ReadStep::NeedMore(reader) if reader.is_empty())
                );
            }
            _ => unreachable!(),
        }
    }
}
