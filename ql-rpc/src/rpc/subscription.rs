use std::{collections::VecDeque, marker::PhantomData};

use bytes::Buf;

use crate::{codec, MethodId, RpcCodec, RpcCodecError, RpcError};

const ITEM_HEADER_SIZE: usize = core::mem::size_of::<u64>();

pub trait Subscription {
    const METHOD: MethodId;
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
    End,
}

pub struct ResponseReader<M: Subscription> {
    bytes: VecDeque<u8>,
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
            bytes: VecDeque::new(),
            marker: PhantomData,
        }
    }

    pub fn push(mut self, chunk: &[u8]) -> Self {
        self.bytes.extend(chunk);
        self
    }

    pub fn advance(self) -> Result<ReadStep<M>, RpcCodecError<M::Error>> {
        let mut this = self;
        let (first, second) = this.bytes.as_slices();
        let Some((consumed, payload_len)) =
            codec::try_measure_next_part(first.chain(second)).map_err(RpcCodecError::Rpc)?
        else {
            return Ok(ReadStep::NeedMore(this));
        };

        if payload_len == 0 {
            if this.bytes.len() == consumed {
                return Ok(ReadStep::End);
            }
            return Err(RpcCodecError::Rpc(RpcError::TrailingBytes));
        }

        this.bytes.drain(..ITEM_HEADER_SIZE);
        let item = {
            let mut body = codec::DrainBuf::new(&mut this.bytes, payload_len);
            M::Event::decode_value(&mut body).map_err(RpcCodecError::Codec)?
        };
        Ok(ReadStep::Item {
            value: item,
            next: this,
        })
    }
}

pub fn encode_request<M: Subscription>(
    request: &M::Request,
    out: &mut Vec<u8>,
) -> Result<(), M::Error> {
    crate::header::RpcHeader::new(M::METHOD).encode_into(out);
    request.encode_value(out)
}

pub fn decode_request<M: Subscription>(mut body: &[u8]) -> Result<M::Request, M::Error> {
    M::Request::decode_value(&mut body)
}

pub fn encode_item<M: Subscription>(
    item: &M::Event,
    out: &mut Vec<u8>,
) -> Result<(), <M::Event as RpcCodec>::Error> {
    codec::encode_value_part(item, out)
}

pub fn encode_end(out: &mut Vec<u8>) {
    codec::push_length(out, 0);
}

#[cfg(test)]
mod tests {
    use bytes::Buf;

    use super::{
        decode_request, encode_end, encode_item, encode_request, ReadStep, ResponseReader,
        Subscription,
    };
    use crate::{parse_inbound, MethodId, RpcCodec};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct BytesValue(Vec<u8>);

    impl RpcCodec for BytesValue {
        type Error = core::convert::Infallible;

        fn encode_value(&self, out: &mut Vec<u8>) -> Result<(), Self::Error> {
            out.extend_from_slice(&self.0);
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
    fn request_round_trip_preserves_header_and_payload() {
        let mut encoded = Vec::new();
        encode_request::<Feed>(&BytesValue(b"watch".to_vec()), &mut encoded).unwrap();

        let inbound = parse_inbound(&encoded).unwrap();
        assert_eq!(inbound.header.method, Feed::METHOD);
        assert_eq!(
            decode_request::<Feed>(inbound.body).unwrap(),
            BytesValue(b"watch".to_vec())
        );
    }

    #[test]
    fn decode_item_stream_reads_all_items() {
        let mut encoded = Vec::new();
        encode_item::<Feed>(&BytesValue(b"one".to_vec()), &mut encoded).unwrap();
        encode_item::<Feed>(&BytesValue(b"two".to_vec()), &mut encoded).unwrap();
        encode_end(&mut encoded);

        let reader = match ResponseReader::<Feed>::new()
            .push(&encoded)
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

    #[test]
    fn response_reader_emits_items_as_chunks_arrive() {
        let mut encoded = Vec::new();
        encode_item::<Feed>(&BytesValue(b"one".to_vec()), &mut encoded).unwrap();
        encode_item::<Feed>(&BytesValue(b"two".to_vec()), &mut encoded).unwrap();
        encode_end(&mut encoded);

        let reader = match ResponseReader::<Feed>::new()
            .push(&encoded[..5])
            .advance()
            .unwrap()
        {
            ReadStep::NeedMore(next) => next,
            _ => unreachable!(),
        };

        let reader = match reader.push(&encoded[5..]).advance().unwrap() {
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
