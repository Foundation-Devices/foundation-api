use std::collections::VecDeque;

use bytes::Buf;

use crate::{RpcCodec, RpcError};

const LENGTH_SIZE: usize = 8;

pub fn encode_value_part<T: RpcCodec>(value: &T, out: &mut Vec<u8>) -> Result<(), T::Error> {
    let mut payload = Vec::new();
    value.encode_value(&mut payload)?;
    push_length(out, payload.len());
    out.extend_from_slice(&payload);
    Ok(())
}

pub fn try_measure_next_part<B: Buf>(mut bytes: B) -> Result<Option<(usize, usize)>, RpcError> {
    if bytes.remaining() < LENGTH_SIZE {
        return Ok(None);
    }

    let len = bytes.get_u64_le();
    let len: usize = len.try_into().map_err(|_| RpcError::LengthOverflow)?;
    let consumed = LENGTH_SIZE
        .checked_add(len)
        .ok_or(RpcError::LengthOverflow)?;
    if bytes.remaining() < len {
        return Ok(None);
    }

    Ok(Some((consumed, len)))
}

pub fn try_measure_next_tagged_part<B: Buf>(
    mut bytes: B,
) -> Result<Option<(u8, usize, usize)>, RpcError> {
    if !bytes.has_remaining() {
        return Ok(None);
    }

    let kind = bytes.get_u8();
    let Some((consumed, len)) = try_measure_next_part(bytes)? else {
        return Ok(None);
    };

    Ok(Some((kind, 1 + consumed, len)))
}

pub struct DrainBuf<'a> {
    bytes: &'a mut VecDeque<u8>,
    offset: usize,
    len: usize,
}

impl<'a> DrainBuf<'a> {
    pub fn new(bytes: &'a mut VecDeque<u8>, len: usize) -> Self {
        debug_assert!(bytes.len() >= len);
        Self {
            bytes,
            offset: 0,
            len,
        }
    }
}

impl Buf for DrainBuf<'_> {
    fn remaining(&self) -> usize {
        self.len - self.offset
    }

    fn chunk(&self) -> &[u8] {
        if self.remaining() == 0 {
            return &[];
        }

        let (first, second) = self.bytes.as_slices();
        if self.offset < first.len() {
            let start = self.offset;
            let end = (start + self.remaining()).min(first.len());
            &first[start..end]
        } else {
            let start = self.offset - first.len();
            let end = (start + self.remaining()).min(second.len());
            &second[start..end]
        }
    }

    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining(), "advanced past payload boundary");
        self.offset += cnt;
    }
}

impl Drop for DrainBuf<'_> {
    fn drop(&mut self) {
        self.bytes.drain(..self.len);
    }
}

pub fn push_length(out: &mut Vec<u8>, len: usize) {
    let len = u64::try_from(len).expect("rpc payload exceeds u64 length framing");
    out.extend_from_slice(&len.to_le_bytes());
}
