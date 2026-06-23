use std::marker::PhantomData;

use bytes::Bytes;

use crate::{chunk_queue::ChunkQueue, RpcCodec, RpcError};

/// reads one length-delimited rpc value from buffered byte chunks
pub struct FramedReader<T: RpcCodec> {
    bytes: ChunkQueue,
    marker: PhantomData<fn() -> T>,
}

pub enum FramedReadStep<T: RpcCodec> {
    NeedMore(FramedReader<T>),
    Value(T),
}

pub enum FramedPrefixStep<T: RpcCodec> {
    NeedMore(FramedReader<T>),
    Value { value: T, bytes: ChunkQueue },
}

impl<T: RpcCodec> Default for FramedReader<T> {
    fn default() -> Self {
        Self {
            bytes: ChunkQueue::default(),
            marker: PhantomData,
        }
    }
}

impl<T: RpcCodec> FramedReader<T> {
    pub fn push(mut self, chunk: Bytes) -> Self {
        self.bytes.push(chunk);
        self
    }

    pub(crate) fn exceeds_total_len(&self, max_len: usize) -> Result<bool, crate::Error> {
        let Some(len) = self.bytes.next_part_total_len()? else {
            return Ok(self.bytes.remaining() > max_len);
        };
        Ok(len > max_len)
    }

    pub fn advance<E>(self) -> Result<FramedReadStep<T>, RpcError<T::Error, E>> {
        match self.advance_prefix::<E>()? {
            FramedPrefixStep::NeedMore(next) => Ok(FramedReadStep::NeedMore(next)),
            FramedPrefixStep::Value { value, bytes } => {
                bytes.expect_empty().map_err(RpcError::Protocol)?;
                Ok(FramedReadStep::Value(value))
            }
        }
    }

    pub fn advance_prefix<E>(self) -> Result<FramedPrefixStep<T>, RpcError<T::Error, E>> {
        let mut this = self;
        let Some(mut body) = this.bytes.try_take_part().map_err(RpcError::Protocol)? else {
            return Ok(FramedPrefixStep::NeedMore(this));
        };

        let value = T::decode_value(&mut body).map_err(RpcError::Codec)?;
        drop(body);
        Ok(FramedPrefixStep::Value {
            value,
            bytes: this.bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{FramedPrefixStep, FramedReadStep, FramedReader};
    use crate::codec::encode_value_part;

    #[test]
    fn value_reader_round_trips_framed_values() {
        let mut encoded = Vec::new();
        encode_value_part(&b"hello".to_vec(), &mut encoded);

        match FramedReader::<Vec<u8>>::default()
            .push(Bytes::from(encoded))
            .advance::<std::convert::Infallible>()
            .unwrap()
        {
            FramedReadStep::Value(value) => assert_eq!(value, b"hello".to_vec()),
            _ => unreachable!(),
        }
    }

    #[test]
    fn value_reader_waits_for_complete_frame() {
        let mut encoded = Vec::new();
        encode_value_part(&b"hello".to_vec(), &mut encoded);
        let encoded = Bytes::from(encoded);

        let reader = match FramedReader::<Vec<u8>>::default()
            .push(encoded.slice(..4))
            .advance::<std::convert::Infallible>()
            .unwrap()
        {
            FramedReadStep::NeedMore(next) => next,
            _ => unreachable!(),
        };

        match reader
            .push(encoded.slice(4..))
            .advance::<std::convert::Infallible>()
            .unwrap()
        {
            FramedReadStep::Value(value) => assert_eq!(value, b"hello".to_vec()),
            _ => unreachable!(),
        }
    }

    #[test]
    fn value_reader_returns_prefix_remainder() {
        let mut encoded = Vec::new();
        encode_value_part(&b"hello".to_vec(), &mut encoded);
        encoded.extend_from_slice(b"tail");

        match FramedReader::<Vec<u8>>::default()
            .push(Bytes::from(encoded))
            .advance_prefix::<std::convert::Infallible>()
            .unwrap()
        {
            FramedPrefixStep::Value { value, mut bytes } => {
                assert_eq!(value, b"hello".to_vec());
                assert_eq!(
                    bytes.pop_front(usize::MAX),
                    Some(Bytes::from_static(b"tail"))
                );
            }
            _ => unreachable!(),
        }
    }
}
