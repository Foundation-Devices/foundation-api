use std::{convert::Infallible, marker::PhantomData, str::Utf8Error};

use bytes::{Buf, BufMut, Bytes};

pub use crate::chunk_queue::ChunkQueue;
use crate::{CodecError, Error};

pub trait RpcCodec: Sized {
    type Error;

    fn encode_value<B: BufMut + ?Sized>(&self, out: &mut B);
    fn decode_value<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error>;
}

impl RpcCodec for String {
    type Error = Utf8Error;

    fn encode_value<B: BufMut + ?Sized>(&self, out: &mut B) {
        out.put_slice(self.as_bytes());
    }

    fn decode_value<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error> {
        let len = bytes.remaining();
        if bytes.chunk().len() == len {
            let s = std::str::from_utf8(bytes.chunk())?.to_owned();
            bytes.advance(len);
            Ok(s)
        } else {
            let mut buf = vec![0; len];
            bytes.copy_to_slice(&mut buf);
            String::from_utf8(buf).map_err(|err| err.utf8_error())
        }
    }
}

impl RpcCodec for Vec<u8> {
    type Error = Infallible;

    fn encode_value<B: BufMut + ?Sized>(&self, out: &mut B) {
        out.put_slice(self.as_slice());
    }

    fn decode_value<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error> {
        let len = bytes.remaining();
        let mut buf = vec![0; len];
        bytes.copy_to_slice(&mut buf);
        Ok(buf)
    }
}

impl RpcCodec for Bytes {
    type Error = Infallible;

    fn encode_value<B: BufMut + ?Sized>(&self, out: &mut B) {
        out.put_slice(self.as_ref());
    }

    fn decode_value<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error> {
        Ok(bytes.copy_to_bytes(bytes.remaining()))
    }
}

const LENGTH_SIZE: usize = 8;

pub fn encode_value_part<T: RpcCodec, B: BufMut + AsMut<[u8]>>(value: &T, out: &mut B) {
    let payload_start = reserve_length(out);
    value.encode_value(out);
    backpatch_length(out, payload_start);
}

/// reads one length-delimited rpc value from buffered byte chunks
pub struct FramedValueReader<T: RpcCodec> {
    bytes: ChunkQueue,
    marker: PhantomData<fn() -> T>,
}

pub enum ReadValueStep<T: RpcCodec> {
    NeedMore(FramedValueReader<T>),
    Value(T),
}

impl<T: RpcCodec> Default for FramedValueReader<T> {
    fn default() -> Self {
        Self {
            bytes: ChunkQueue::default(),
            marker: PhantomData,
        }
    }
}

impl<T: RpcCodec> FramedValueReader<T> {
    pub fn push(mut self, chunk: Bytes) -> Self {
        self.bytes.push(chunk);
        self
    }

    pub fn into_bytes(self) -> ChunkQueue {
        self.bytes
    }

    pub fn advance(self) -> Result<ReadValueStep<T>, CodecError<T::Error>> {
        let mut this = self;
        let Some(mut body) = this.bytes.try_take_part()? else {
            return Ok(ReadValueStep::NeedMore(this));
        };

        let value = T::decode_value(&mut body).map_err(CodecError::Codec)?;
        drop(body);
        if this.bytes.remaining() > 0 {
            return Err(CodecError::Rpc(Error::TrailingBytes));
        }
        Ok(ReadValueStep::Value(value))
    }
}

pub fn reserve_length<B: BufMut + AsMut<[u8]>>(out: &mut B) -> usize {
    let start = out.as_mut().len();
    out.put_u64_le(0);
    start
}

pub fn backpatch_length<B: AsMut<[u8]> + ?Sized>(out: &mut B, start: usize) {
    let out = out.as_mut();
    let payload_start = start + LENGTH_SIZE;
    let payload_len = out.len() - payload_start;
    let payload_len = u64::try_from(payload_len).expect("rpc payload exceeds u64 length framing");
    out[start..payload_start].copy_from_slice(&payload_len.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{encode_value_part, FramedValueReader, ReadValueStep};

    #[test]
    fn value_reader_round_trips_framed_values() {
        let mut encoded = Vec::new();
        encode_value_part(&b"hello".to_vec(), &mut encoded);

        match FramedValueReader::<Vec<u8>>::default()
            .push(Bytes::from(encoded))
            .advance()
            .unwrap()
        {
            ReadValueStep::Value(value) => assert_eq!(value, b"hello".to_vec()),
            _ => unreachable!(),
        }
    }

    #[test]
    fn value_reader_waits_for_complete_frame() {
        let mut encoded = Vec::new();
        encode_value_part(&b"hello".to_vec(), &mut encoded);
        let encoded = Bytes::from(encoded);

        let reader = match FramedValueReader::<Vec<u8>>::default()
            .push(encoded.slice(..4))
            .advance()
            .unwrap()
        {
            ReadValueStep::NeedMore(next) => next,
            _ => unreachable!(),
        };

        match reader.push(encoded.slice(4..)).advance().unwrap() {
            ReadValueStep::Value(value) => assert_eq!(value, b"hello".to_vec()),
            _ => unreachable!(),
        }
    }
}
