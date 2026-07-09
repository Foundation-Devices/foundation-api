use core::mem::ManuallyDrop;

use crate::{varint, ByteSlice, Decode, Error};

#[derive(Clone)]
pub struct Reader<B> {
    remaining: ManuallyDrop<B>,
}

impl<B: ByteSlice> Reader<B> {
    #[inline]
    pub fn new(bytes: B) -> Self {
        Self {
            remaining: ManuallyDrop::new(bytes),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    #[inline]
    pub fn remaining_len(&self) -> usize {
        self.remaining.len()
    }

    pub fn take_n(&mut self, len: usize) -> Result<B, Error> {
        if len > self.remaining.len() {
            return Err(Error::UnexpectedEof);
        }
        // SAFETY: checked above
        let (head, tail) = unsafe {
            let remaining = ManuallyDrop::take(&mut self.remaining);
            remaining.split_at_unchecked(len)
        };
        self.remaining = ManuallyDrop::new(tail);
        Ok(head)
    }

    #[inline]
    pub fn take_u8(&mut self) -> Result<u8, Error> {
        self.remaining.take_u8().ok_or(Error::UnexpectedEof)
    }

    pub fn take_all(&mut self) -> B {
        // SAFETY: 0 is always a valid split point
        let (empty, rest) = unsafe {
            let remaining = ManuallyDrop::take(&mut self.remaining);
            remaining.split_at_unchecked(0)
        };
        self.remaining = ManuallyDrop::new(empty);
        rest
    }

    pub fn take_len_prefixed(&mut self) -> Result<B, Error> {
        let len = self.decode_varint::<usize>()?;
        self.take_n(len)
    }

    #[inline]
    pub fn decode<T>(&mut self) -> Result<T, Error>
    where
        T: Decode<B>,
    {
        T::decode(self)
    }

    #[inline]
    pub fn decode_varint<T>(&mut self) -> Result<T, Error>
    where
        T: varint::VarInt,
    {
        varint::decode(self)
    }
}

impl<B> Drop for Reader<B> {
    fn drop(&mut self) {
        // SAFETY: `remaining` is initialized except during `take_bytes`
        unsafe {
            ManuallyDrop::drop(&mut self.remaining);
        }
    }
}
