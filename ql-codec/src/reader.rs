use crate::{varint, ByteSlice, Decode, Error};

#[derive(Clone)]
pub struct Reader<B> {
    remaining: B,
}

impl<B: ByteSlice> Reader<B> {
    #[inline]
    pub fn new(bytes: B) -> Self {
        Self { remaining: bytes }
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
        Ok(self.remaining.split_off_front(len))
    }

    #[inline]
    pub fn take_u8(&mut self) -> Result<u8, Error> {
        self.remaining.take_u8().ok_or(Error::UnexpectedEof)
    }

    pub fn take_all(&mut self) -> B {
        self.remaining.split_off_front(self.remaining.len())
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
        T: varint::Primitive,
    {
        varint::decode(self)
    }
}
