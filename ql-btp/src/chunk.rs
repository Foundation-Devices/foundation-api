use std::sync::atomic::{AtomicU32, Ordering};

use bytes::BufMut;
use consts::APP_MTU;
use ql_codec::Encode;

use crate::{Header, CHUNK_DATA_SIZE, MAX_RECORD_SIZE};

pub struct Chunker<'a> {
    data: &'a [u8],
    sequence: u16,
    index: u16,
}

impl Iterator for Chunker<'_> {
    type Item = [u8; APP_MTU];

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.index as usize * CHUNK_DATA_SIZE;
        if start >= self.data.len() {
            return None;
        }
        let data = self
            .data
            .get(start..(start + CHUNK_DATA_SIZE).min(self.data.len()))?;
        let header = Header {
            sequence: self.sequence,
            index: self.index,
            record_len: self.data.len() as u32,
        };
        let mut chunk = [0; APP_MTU];
        let mut output = &mut chunk[..];
        header.encode(&mut output);
        output.put_slice(data);
        self.index += 1;
        Some(chunk)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.data.len() - self.index as usize * CHUNK_DATA_SIZE;
        let chunks = remaining.div_ceil(CHUNK_DATA_SIZE);
        (chunks, Some(chunks))
    }
}

impl ExactSizeIterator for Chunker<'_> {}

pub fn chunk(data: &[u8]) -> Chunker<'_> {
    static NEXT_SEQUENCE: AtomicU32 = AtomicU32::new(0);
    let sequence = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed) as u16;
    chunk_with_sequence(data, sequence)
}

pub fn chunk_with_sequence(data: &[u8], sequence: u16) -> Chunker<'_> {
    debug_assert!(!data.is_empty());
    debug_assert!(data.len() <= MAX_RECORD_SIZE);
    Chunker {
        data,
        sequence,
        index: 0,
    }
}
