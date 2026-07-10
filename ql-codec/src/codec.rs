use bytes::{Buf, BufMut};

use crate::{varint, BufView, ByteSlice, Decode, Encode, Error, Reader};

impl<B: ByteSlice, const N: usize> Decode<B> for [u8; N] {
    fn decode(reader: &mut Reader<B>) -> Result<Self, Error> {
        let bytes = reader.take_n(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

impl<const N: usize> Encode for [u8; N] {
    fn encoded_len(&self) -> usize {
        N
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        out.put_slice(self);
    }
}

impl<B: ByteSlice, const N: usize> Decode<B> for Box<[u8; N]> {
    fn decode(reader: &mut Reader<B>) -> Result<Self, Error> {
        let bytes = reader.take_n(N)?;
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

impl<const N: usize> Encode for Box<[u8; N]> {
    fn encoded_len(&self) -> usize {
        N
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        out.put_slice(self.as_ref());
    }
}

macro_rules! impl_codec {
    (byte_encode: $($ty:ty),* $(,)?) => {
        $(
            impl Encode for $ty {
                fn encoded_len(&self) -> usize {
                    encoded_len_bytes(self)
                }
                fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
                    encode_bytes(self, out);
                }
            }
        )*
    };
    (owned_byte_decode: $($ty:ty),* $(,)?) => {
        $(
            impl<B: ByteSlice> Decode<B> for $ty {
                fn decode(reader: &mut Reader<B>) -> Result<Self, Error> {
                    Ok(<$ty>::from(&*reader.take_len_prefixed()?))
                }
            }
        )*
    };
    (fixed_integer: $($ty:ty),* $(,)?) => {
        $(
            impl<B: ByteSlice> Decode<B> for $ty {
                fn decode(reader: &mut Reader<B>) -> Result<Self, Error> {
                    Ok(Self::from_le_bytes(reader.decode()?))
                }
            }
            impl Encode for $ty {
                fn encoded_len(&self) -> usize {
                    size_of::<Self>()
                }
                fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
                    out.put_slice(&self.to_le_bytes());
                }
            }
        )*
    };
}

impl_codec!(byte_encode: [u8], Vec<u8>, Box<[u8]>, bytes::Bytes);

impl<'a> Decode<&'a [u8]> for &'a [u8] {
    fn decode(reader: &mut Reader<&'a [u8]>) -> Result<Self, Error> {
        reader.take_len_prefixed()
    }
}

impl<'a> Decode<&'a mut [u8]> for &'a mut [u8] {
    fn decode(reader: &mut Reader<&'a mut [u8]>) -> Result<Self, Error> {
        reader.take_len_prefixed()
    }
}

impl Decode<bytes::Bytes> for bytes::Bytes {
    fn decode(reader: &mut Reader<bytes::Bytes>) -> Result<Self, Error> {
        reader.take_len_prefixed()
    }
}

impl_codec!(owned_byte_decode: Vec<u8>, Box<[u8]>);

impl Encode for str {
    fn encoded_len(&self) -> usize {
        self.as_bytes().encoded_len()
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        self.as_bytes().encode(out);
    }
}

impl<'a> Decode<&'a [u8]> for &'a str {
    fn decode(reader: &mut Reader<&'a [u8]>) -> Result<Self, Error> {
        std::str::from_utf8(reader.take_len_prefixed()?).map_err(|_| Error::InvalidUtf8)
    }
}

impl Encode for String {
    fn encoded_len(&self) -> usize {
        self.as_str().encoded_len()
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        self.as_str().encode(out);
    }
}

impl<B: ByteSlice> Decode<B> for String {
    fn decode(reader: &mut Reader<B>) -> Result<Self, Error> {
        let bytes = reader.take_len_prefixed()?;
        std::str::from_utf8(&bytes)
            .map(str::to_owned)
            .map_err(|_| Error::InvalidUtf8)
    }
}

impl<B: ByteSlice> Decode<B> for u8 {
    fn decode(reader: &mut Reader<B>) -> Result<Self, Error> {
        reader.take_u8()
    }
}

impl Encode for u8 {
    fn encoded_len(&self) -> usize {
        size_of::<Self>()
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u8(*self);
    }
}

impl_codec!(fixed_integer: u16, u32, u64);

impl<B: ByteSlice> Decode<B> for bool {
    fn decode(reader: &mut Reader<B>) -> Result<Self, Error> {
        match reader.decode::<u8>()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidDiscriminant),
        }
    }
}

impl Encode for bool {
    fn encoded_len(&self) -> usize {
        size_of::<u8>()
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u8(u8::from(*self));
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encoded_len(&self) -> usize {
        1 + self.as_ref().map_or(0, Encode::encoded_len)
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        match self {
            None => out.put_u8(0),
            Some(inner) => {
                out.put_u8(1);
                inner.encode(out);
            }
        }
    }
}

impl<B: ByteSlice, T: Decode<B>> Decode<B> for Option<T> {
    fn decode(reader: &mut Reader<B>) -> Result<Self, Error> {
        match reader.decode::<u8>()? {
            0 => Ok(None),
            1 => Ok(Some(reader.decode::<T>()?)),
            _ => Err(Error::InvalidDiscriminant),
        }
    }
}

pub fn encoded_len_bytes<B: BufView + ?Sized>(bytes: &B) -> usize {
    let len = bytes.buf().remaining();
    varint::encoded_len(len) + len
}

pub fn encode_bytes<B, W>(bytes: &B, out: &mut W)
where
    B: BufView + ?Sized,
    W: BufMut + ?Sized,
{
    let mut bytes = bytes.buf();
    varint::encode(bytes.remaining(), out);
    while bytes.has_remaining() {
        let chunk = bytes.chunk();
        out.put_slice(chunk);
        bytes.advance(chunk.len());
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn integers_are_little_endian() {
        assert_eq!(0x1234u16.encode_vec(), [0x34, 0x12]);
        assert_eq!(0x1234_5678u32.encode_vec(), [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(
            0x0123_4567_89ab_cdefu64.encode_vec(),
            [0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]
        );
        assert_eq!(u16::decode_bytes([0x34, 0x12].as_slice()), Ok(0x1234));
        assert_eq!(
            u32::decode_bytes([0x78, 0x56, 0x34, 0x12].as_slice()),
            Ok(0x1234_5678)
        );
    }

    #[test]
    fn byte_containers_use_varint_prefix() {
        let bytes = [1u8, 2, 3];

        let encoded = bytes[..].encode_vec();
        assert_eq!(encoded, [3, 1, 2, 3]);
        assert_eq!(bytes.to_vec().encode_vec(), encoded);
        assert_eq!(Box::<[u8]>::from(bytes).encode_vec(), encoded);
        assert_eq!(Bytes::copy_from_slice(&bytes).encode_vec(), encoded);

        let decoded = <&[u8]>::decode_bytes(encoded.as_slice()).unwrap();
        assert_eq!(decoded, [1, 2, 3]);
        assert_eq!(
            Vec::<u8>::decode_bytes(encoded.as_slice()).unwrap(),
            [1, 2, 3]
        );
        assert_eq!(
            Box::<[u8]>::decode_bytes(encoded.as_slice())
                .unwrap()
                .as_ref(),
            [1, 2, 3]
        );

        let encoded = String::from("hello").encode_vec();
        assert_eq!(encoded, [5, b'h', b'e', b'l', b'l', b'o']);
        assert_eq!(<&str>::decode_bytes(encoded.as_slice()).unwrap(), "hello");
        assert_eq!(String::decode_bytes(encoded.as_slice()).unwrap(), "hello");
        assert_eq!(
            String::decode_bytes([1, 0xff].as_slice()),
            Err(Error::InvalidUtf8)
        );
    }
}
