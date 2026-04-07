use std::collections::VecDeque;

use bytes::{Buf, BufMut, Bytes};

use crate::{RpcCodec, RpcError};

const LENGTH_SIZE: usize = 8;

pub fn encode_value_part<T: RpcCodec, B: BufMut + AsMut<[u8]>>(
    value: &T,
    out: &mut B,
) -> Result<(), T::Error> {
    let payload_start = reserve_length(out);
    value.encode_value(out)?;
    backpatch_length(out, payload_start);
    Ok(())
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

    pub fn try_take_part(&mut self) -> Result<Option<DrainBuf<'_>>, RpcError> {
        let Some(len) = self.peek_next_part_len()? else {
            return Ok(None);
        };
        self.advance(LENGTH_SIZE);
        Ok(Some(DrainBuf::new(self, len)))
    }

    pub fn try_take_tagged_part(&mut self) -> Result<Option<(u8, DrainBuf<'_>)>, RpcError> {
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

    fn peek_next_part_len(&self) -> Result<Option<usize>, RpcError> {
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

    pub(crate) fn advance_inner(&mut self, mut cnt: usize) {
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

fn read_next_part_len<B: Buf>(bytes: &mut B) -> Result<Option<usize>, RpcError> {
    let Ok(len) = bytes.try_get_u64_le() else {
        return Ok(None);
    };
    let len: usize = len.try_into().map_err(|_| RpcError::LengthOverflow)?;
    if bytes.remaining() < len {
        return Ok(None);
    }
    Ok(Some(len))
}

pub fn push_length<B: BufMut + ?Sized>(out: &mut B, len: usize) {
    let len = u64::try_from(len).expect("rpc payload exceeds u64 length framing");
    out.put_u64_le(len);
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
