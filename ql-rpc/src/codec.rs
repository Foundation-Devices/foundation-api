use std::{collections::VecDeque, convert::Infallible, marker::PhantomData, str::Utf8Error};

use bytes::{Buf, BufMut, Bytes};

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

pub enum ReadValueStep<T: RpcCodec> {
    NeedMore(ValueReader<T>),
    Value(T),
}

pub struct ValueReader<T: RpcCodec> {
    bytes: ChunkQueue,
    marker: PhantomData<fn() -> T>,
}

impl<T: RpcCodec> Default for ValueReader<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: RpcCodec> ValueReader<T> {
    pub fn new() -> Self {
        Self {
            bytes: ChunkQueue::new(),
            marker: PhantomData,
        }
    }

    pub fn push(mut self, chunk: Bytes) -> Self {
        self.bytes.push(chunk);
        self
    }

    pub fn advance(self) -> Result<ReadValueStep<T>, CodecError<T::Error>> {
        let mut this = self;
        let Some(mut body) = this.bytes.try_take_part().map_err(CodecError::Rpc)? else {
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

#[derive(Debug, Default)]
pub struct ChunkQueue {
    chunks: VecDeque<Bytes>,
    remaining: usize,
}

impl ChunkQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, chunk: Bytes) {
        if chunk.is_empty() {
            return;
        }
        self.remaining += chunk.len();
        self.chunks.push_back(chunk);
    }

    pub fn remaining(&self) -> usize {
        self.remaining
    }

    pub fn try_take_part(&mut self) -> Result<Option<DrainBuf<'_>>, Error> {
        let Some(len) = self.peek_next_part_len()? else {
            return Ok(None);
        };
        self.advance(LENGTH_SIZE);
        Ok(Some(DrainBuf::new(self, len)))
    }

    pub fn try_take_tagged_part(&mut self) -> Result<Option<(u8, DrainBuf<'_>)>, Error> {
        let mut bytes = self.peek();
        let Ok(kind) = bytes.try_get_u8() else {
            return Ok(None);
        };
        let Some(len) = read_next_part_len(&mut bytes)? else {
            return Ok(None);
        };

        self.advance(1 + LENGTH_SIZE);
        Ok(Some((kind, DrainBuf::new(self, len))))
    }

    fn peek_next_part_len(&self) -> Result<Option<usize>, Error> {
        let mut bytes = self.peek();
        read_next_part_len(&mut bytes)
    }

    fn peek(&self) -> ChunkQueuePeek<'_> {
        ChunkQueuePeek {
            chunks: &self.chunks,
            chunk_index: 0,
            chunk_offset: 0,
            remaining: self.remaining,
        }
    }

    fn front_chunk(&self, limit: usize) -> &[u8] {
        let Some(chunk) = self.chunks.front() else {
            return &[];
        };
        &chunk[..chunk.len().min(limit)]
    }

    fn advance_inner(&mut self, mut cnt: usize) {
        assert!(cnt <= self.remaining, "advanced past buffered data");
        self.remaining -= cnt;
        while cnt > 0 {
            let front = self.chunks.front_mut().expect("buffered data present");
            let consumed = cnt.min(front.len());
            front.advance(consumed);
            cnt -= consumed;
            if front.is_empty() {
                self.chunks.pop_front();
            }
        }
    }
}

struct ChunkQueuePeek<'a> {
    chunks: &'a VecDeque<Bytes>,
    chunk_index: usize,
    chunk_offset: usize,
    remaining: usize,
}

impl Buf for ChunkQueuePeek<'_> {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        if self.remaining == 0 {
            return &[];
        }

        let Some(chunk) = self.chunks.get(self.chunk_index) else {
            return &[];
        };
        &chunk[self.chunk_offset..]
    }

    fn advance(&mut self, mut cnt: usize) {
        assert!(cnt <= self.remaining, "advanced past buffered data");
        self.remaining -= cnt;

        while cnt > 0 {
            let chunk = self
                .chunks
                .get(self.chunk_index)
                .expect("buffered data present");
            let available = chunk.len() - self.chunk_offset;
            let step = cnt.min(available);
            self.chunk_offset += step;
            cnt -= step;
            if self.chunk_offset == chunk.len() {
                self.chunk_index += 1;
                self.chunk_offset = 0;
            }
        }
    }
}

impl Buf for ChunkQueue {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        self.front_chunk(self.remaining)
    }

    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining, "advanced past buffered data");
        self.advance_inner(cnt);
    }
}

pub struct DrainBuf<'a> {
    bytes: &'a mut ChunkQueue,
    remaining: usize,
}

impl<'a> DrainBuf<'a> {
    pub fn new(bytes: &'a mut ChunkQueue, len: usize) -> Self {
        debug_assert!(bytes.remaining() >= len);
        Self {
            bytes,
            remaining: len,
        }
    }
}

impl Buf for DrainBuf<'_> {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        self.bytes.front_chunk(self.remaining)
    }

    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining(), "advanced past payload boundary");
        self.bytes.advance_inner(cnt);
        self.remaining -= cnt;
    }
}

impl Drop for DrainBuf<'_> {
    fn drop(&mut self) {
        if self.remaining > 0 {
            self.bytes.advance_inner(self.remaining);
            self.remaining = 0;
        }
    }
}

fn read_next_part_len<B: Buf>(bytes: &mut B) -> Result<Option<usize>, Error> {
    let Ok(len) = bytes.try_get_u64_le() else {
        return Ok(None);
    };
    let len: usize = len.try_into().map_err(|_| Error::LengthOverflow)?;
    if bytes.remaining() < len {
        return Ok(None);
    }
    Ok(Some(len))
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
    use bytes::{Buf, BufMut, Bytes};

    use super::{encode_value_part, ReadValueStep, ValueReader};
    use crate::RpcCodec;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct BytesValue(Vec<u8>);

    impl RpcCodec for BytesValue {
        type Error = core::convert::Infallible;

        fn encode_value<B: BufMut + ?Sized>(&self, out: &mut B) {
            out.put_slice(&self.0);
        }

        fn decode_value<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error> {
            Ok(Self(bytes.copy_to_bytes(bytes.remaining()).to_vec()))
        }
    }

    #[test]
    fn value_reader_round_trips_framed_values() {
        let mut encoded = Vec::new();
        encode_value_part(&BytesValue(b"hello".to_vec()), &mut encoded);

        match ValueReader::<BytesValue>::new()
            .push(Bytes::from(encoded))
            .advance()
            .unwrap()
        {
            ReadValueStep::Value(value) => assert_eq!(value, BytesValue(b"hello".to_vec())),
            _ => unreachable!(),
        }
    }

    #[test]
    fn value_reader_waits_for_complete_frame() {
        let mut encoded = Vec::new();
        encode_value_part(&BytesValue(b"hello".to_vec()), &mut encoded);
        let encoded = Bytes::from(encoded);

        let reader = match ValueReader::<BytesValue>::new()
            .push(encoded.slice(..4))
            .advance()
            .unwrap()
        {
            ReadValueStep::NeedMore(next) => next,
            _ => unreachable!(),
        };

        match reader.push(encoded.slice(4..)).advance().unwrap() {
            ReadValueStep::Value(value) => assert_eq!(value, BytesValue(b"hello".to_vec())),
            _ => unreachable!(),
        }
    }
}
