use bytes::BufMut;

use crate::{ByteSlice, WireError};

pub trait WireEncode {
    fn encoded_len(&self) -> usize;

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W);

    fn encode_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out);
        debug_assert_eq!(out.len(), self.encoded_len());
        out
    }
}

pub trait WireDecode<B: ByteSlice>: Sized {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError>;

    fn decode_bytes(bytes: B) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes);
        Self::decode(&mut reader)
    }

    fn decode_exact(bytes: B) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes);
        let value = Self::decode(&mut reader)?;
        if reader.is_empty() {
            Ok(value)
        } else {
            Err(WireError::InvalidPayload)
        }
    }
}

impl<B: ByteSlice, const N: usize> WireDecode<B> for [u8; N] {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        let bytes = reader.take_bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

impl<const N: usize> WireEncode for [u8; N] {
    fn encoded_len(&self) -> usize {
        N
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        out.put_slice(self);
    }
}

impl<B: ByteSlice, const N: usize> WireDecode<B> for Box<[u8; N]> {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        let bytes = reader.take_bytes(N)?;
        let mut out = Self::new_uninit();
        let src = bytes.as_ptr();
        let dst = out.as_mut_ptr().cast::<u8>();
        // SAFETY: `take_bytes(N)` guarantees the source has exactly `N` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(src, dst, N);
            Ok(out.assume_init())
        }
    }
}

impl<const N: usize> WireEncode for Box<[u8; N]> {
    fn encoded_len(&self) -> usize {
        N
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        out.put_slice(self.as_ref());
    }
}

impl WireEncode for [u8] {
    fn encoded_len(&self) -> usize {
        self.len()
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        out.put_slice(self);
    }
}

impl<B: ByteSlice> WireDecode<B> for u8 {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        Ok(reader.take_bytes(1)?[0])
    }
}

impl WireEncode for u8 {
    fn encoded_len(&self) -> usize {
        size_of::<Self>()
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u8(*self);
    }
}

impl<B: ByteSlice> WireDecode<B> for u16 {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        Ok(Self::from_be_bytes(reader.decode()?))
    }
}

impl WireEncode for u16 {
    fn encoded_len(&self) -> usize {
        size_of::<Self>()
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u16(*self);
    }
}

impl<B: ByteSlice> WireDecode<B> for u32 {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        Ok(Self::from_be_bytes(reader.decode()?))
    }
}

impl WireEncode for u32 {
    fn encoded_len(&self) -> usize {
        size_of::<Self>()
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u32(*self);
    }
}

impl<B: ByteSlice> WireDecode<B> for u64 {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        Ok(Self::from_be_bytes(reader.decode()?))
    }
}

impl WireEncode for u64 {
    fn encoded_len(&self) -> usize {
        size_of::<Self>()
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u64(*self);
    }
}

impl<B: ByteSlice> WireDecode<B> for bool {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        match reader.decode::<u8>()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::InvalidPayload),
        }
    }
}

impl WireEncode for bool {
    fn encoded_len(&self) -> usize {
        size_of::<u8>()
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u8(u8::from(*self));
    }
}

impl<T: WireEncode> WireEncode for Option<T> {
    fn encoded_len(&self) -> usize {
        1 + self.as_ref().map_or(0, |inner| inner.encoded_len())
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        match self {
            None => out.put_u8(0),
            Some(inner) => {
                out.put_u8(1);
                inner.encode(out)
            }
        }
    }
}

impl<B: ByteSlice, T: WireDecode<B>> WireDecode<B> for Option<T> {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        match reader.decode::<u8>()? {
            0 => Ok(None),
            1 => Ok(Some(reader.decode::<T>()?)),
            _ => Err(WireError::InvalidPayload),
        }
    }
}

pub struct Reader<B> {
    remaining: Option<B>,
}

impl<B: ByteSlice> Reader<B> {
    pub fn new(bytes: B) -> Self {
        Self {
            remaining: Some(bytes),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.remaining.as_ref().unwrap().is_empty()
    }

    pub fn remaining_len(&self) -> usize {
        self.remaining.as_ref().unwrap().len()
    }

    pub fn take_bytes(&mut self, len: usize) -> Result<B, WireError> {
        let remaining = self.remaining.take().unwrap();
        match remaining.split_at(len) {
            Ok((head, tail)) => {
                self.remaining = Some(tail);
                Ok(head)
            }
            Err(remaining) => {
                self.remaining = Some(remaining);
                Err(WireError::InvalidPayload)
            }
        }
    }

    pub fn take_rest(&mut self) -> B {
        self.take_bytes(self.remaining_len()).unwrap()
    }

    #[inline]
    pub fn decode<T>(&mut self) -> Result<T, WireError>
    where
        T: WireDecode<B>,
    {
        T::decode(self)
    }
}
