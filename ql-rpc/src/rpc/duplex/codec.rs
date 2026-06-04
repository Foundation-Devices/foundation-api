use std::marker::PhantomData;

use bytes::{BufMut, Bytes};

use crate::{codec, CodecError, RpcCodec};

pub fn encode_event<T>(event: &T, out: &mut (impl BufMut + AsMut<[u8]>))
where
    T: RpcCodec,
{
    codec::encode_value_part(event, out)
}

pub enum ReadStep<T: RpcCodec> {
    NeedMore,
    Event(T),
}

pub struct EventReader<T: RpcCodec> {
    bytes: codec::ChunkQueue,
    marker: PhantomData<fn() -> T>,
}

impl<T: RpcCodec> Default for EventReader<T> {
    fn default() -> Self {
        Self {
            bytes: codec::ChunkQueue::default(),
            marker: PhantomData,
        }
    }
}

impl<T: RpcCodec> EventReader<T> {
    pub fn push(&mut self, chunk: Bytes) {
        self.bytes.push(chunk);
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.remaining() == 0
    }

    pub fn advance(&mut self) -> Result<ReadStep<T>, CodecError<T::Error>> {
        let Some(mut body) = self.bytes.try_take_part()? else {
            return Ok(ReadStep::NeedMore);
        };

        let value = {
            let value = T::decode_value(&mut body).map_err(CodecError::Codec)?;
            drop(body);
            value
        };
        Ok(ReadStep::Event(value))
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{encode_event, EventReader, ReadStep};

    #[test]
    fn event_reader_emits_multiple_events() {
        let mut encoded = Vec::new();
        encode_event(&b"one".to_vec(), &mut encoded);
        encode_event(&b"two".to_vec(), &mut encoded);

        let mut reader = EventReader::<Vec<u8>>::default();
        reader.push(Bytes::from(encoded));

        match reader.advance().unwrap() {
            ReadStep::Event(value) => {
                assert_eq!(value, b"one".to_vec());
            }
            _ => unreachable!(),
        };

        match reader.advance().unwrap() {
            ReadStep::Event(value) => {
                assert_eq!(value, b"two".to_vec());
                assert!(reader.is_empty());
            }
            _ => unreachable!(),
        }
    }
}
