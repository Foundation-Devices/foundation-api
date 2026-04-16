use std::{
    future::poll_fn,
    marker::PhantomData,
    task::{Context, Poll},
};

use bytes::{BufMut, Bytes};

use crate::{codec, CallError, CodecError, RouteId, RpcCodec, RpcRead};

pub trait Subscription {
    const ROUTE: RouteId;
    type Error;
    type Request: RpcCodec<Error = Self::Error>;
    type Event: RpcCodec<Error = Self::Error>;
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

pub struct SubscriptionCall<M, R>
where
    M: Subscription,
    R: RpcRead,
{
    stream: R,
    reader: Option<ResponseReader<M>>,
}

impl<M, R> SubscriptionCall<M, R>
where
    M: Subscription,
    R: RpcRead,
{
    pub fn new(stream: R) -> Self {
        Self {
            stream,
            reader: Some(ResponseReader::default()),
        }
    }

    pub async fn next_event(&mut self) -> Option<Result<M::Event, CallError<M::Error, R::Error>>> {
        poll_fn(|cx| self.poll_next_event(cx)).await
    }

    pub fn poll_next_event(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<M::Event, CallError<M::Error, R::Error>>>> {
        loop {
            let Some(reader) = self.reader.take() else {
                return Poll::Ready(None);
            };

            let reader = match reader.advance() {
                Ok(ReadStep::Item { value, next }) => {
                    self.reader = Some(next);
                    return Poll::Ready(Some(Ok(value)));
                }
                Ok(ReadStep::NeedMore(next)) => next,
                Err(error) => return Poll::Ready(Some(Err(error.into()))),
            };

            match self.stream.poll_read(usize::MAX, cx) {
                Poll::Ready(Ok(Some(chunk))) => {
                    self.reader = Some(reader.push(chunk));
                }
                Poll::Ready(Ok(None)) => {
                    if reader.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Err(crate::Error::Truncated.into())));
                }
                Poll::Ready(Err(error)) => {
                    self.reader = None;
                    return Poll::Ready(Some(Err(CallError::Transport(error))));
                }
                Poll::Pending => {
                    self.reader = Some(reader);
                    return Poll::Pending;
                }
            }
        }
    }

    pub fn into_inner(self) -> R {
        self.stream
    }
}

impl<M: Subscription> Default for ResponseReader<M> {
    fn default() -> Self {
        Self {
            bytes: codec::ChunkQueue::new(),
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

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{encode_item, ReadStep, ResponseReader, Subscription};
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

        let reader = match ResponseReader::<Feed>::default()
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

        let reader = match ResponseReader::<Feed>::default()
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

        match ResponseReader::<Feed>::default()
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
