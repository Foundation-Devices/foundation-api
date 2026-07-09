use bytes::BufMut;

use crate::{ByteSlice, Error, Reader};

pub trait VarInt: Copy {
    const MAX_ENCODED_LEN: usize;

    fn from_u8(value: u8) -> Self;
    fn low_7_bits(self) -> u8;
    fn shr_7(self) -> Self;
    fn needs_more(self) -> bool;
    fn checked_add_payload(self, payload: u8, shift: usize) -> Option<Self>;
}

pub fn encoded_len<T: VarInt>(mut value: T) -> usize {
    let mut len = 1;
    while value.needs_more() {
        value = value.shr_7();
        len += 1;
    }
    len
}

pub fn encode<T, W>(mut value: T, out: &mut W)
where
    T: VarInt,
    W: BufMut + ?Sized,
{
    while value.needs_more() {
        out.put_u8(value.low_7_bits() | 0x80);
        value = value.shr_7();
    }
    out.put_u8(value.low_7_bits());
}

pub fn decode<T, B>(reader: &mut Reader<B>) -> Result<T, Error>
where
    T: VarInt,
    B: ByteSlice,
{
    let mut value = T::from_u8(0);

    for index in 0..T::MAX_ENCODED_LEN {
        let byte = reader.decode::<u8>()?;
        let payload = byte & 0x7f;

        value = value
            .checked_add_payload(payload, index * 7)
            .ok_or(Error::InvalidVarint)?;

        if byte & 0x80 == 0 {
            if index > 0 && payload == 0 {
                return Err(Error::InvalidVarint);
            }
            return Ok(value);
        }
    }

    Err(Error::InvalidVarint)
}

macro_rules! impl_varint {
    ($($ty:ty),* $(,)?) => {
        $(
            impl VarInt for $ty {
                const MAX_ENCODED_LEN: usize = (size_of::<Self>() * 8).div_ceil(7);

                #[inline]
                fn from_u8(value: u8) -> Self {
                    Self::from(value)
                }
                #[inline]
                #[allow(clippy::cast_possible_truncation)]
                fn low_7_bits(self) -> u8 {
                    (self & 0x7f) as u8
                }
                #[inline]
                fn shr_7(self) -> Self {
                    self >> 7
                }
                #[inline]
                fn needs_more(self) -> bool {
                    self >= 0x80
                }
                #[inline]
                fn checked_add_payload(self, payload: u8, shift: usize) -> Option<Self> {
                    let bit_width = size_of::<Self>() * 8;
                    if shift >= bit_width {
                        return (payload == 0).then_some(self);
                    }
                    let max_payload = Self::MAX >> shift;
                    let payload = Self::from(payload);
                    if payload > max_payload {
                        return None;
                    }
                    Some(self | (payload << shift))
                }
            }
        )*
    };
}

impl_varint!(u8, u16, u32, u64, usize);

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::*;

    fn assert_decodes<T>(value: T)
    where
        T: VarInt + Debug + PartialEq,
    {
        let mut out = Vec::new();
        encode(value, &mut out);
        assert_eq!(out.len(), encoded_len(value));
        let mut reader = Reader::new(out.as_slice());
        assert_eq!(decode(&mut reader), Ok(value));
        assert!(reader.is_empty());
    }

    fn assert_error<T>(bytes: &[u8], error: Error)
    where
        T: VarInt + Debug + PartialEq,
    {
        let mut reader = Reader::new(bytes);
        assert_eq!(decode::<T, _>(&mut reader), Err(error));
    }

    fn test_type<T>(max: T)
    where
        T: VarInt + Debug + PartialEq + TryFrom<u64>,
    {
        for value in [0, 1, 127].map(T::from_u8) {
            assert_decodes(value);
        }
        for shift in (7..size_of::<T>() * 8).step_by(7) {
            let boundary = 1u64 << shift;
            if let (Ok(before), Ok(after)) = (T::try_from(boundary - 1), T::try_from(boundary)) {
                assert_decodes(before);
                assert_decodes(after);
            }
        }
        assert_decodes(max);

        let mut encoded = Vec::new();
        encode(T::from_u8(127), &mut encoded);
        encoded.push(0x55);
        let mut reader = Reader::new(encoded.as_slice());
        assert_eq!(decode(&mut reader), Ok(T::from_u8(127)));
        assert_eq!(reader.take_all(), &[0x55]);

        assert_error::<T>(&[0x80, 0x00], Error::InvalidVarint);
        assert_error::<T>(&[0x80], Error::UnexpectedEof);
        assert_error::<T>(&vec![0xff; T::MAX_ENCODED_LEN], Error::InvalidVarint);

        let bit_width = size_of::<T>() * 8;
        let mut overflow = vec![0x80; bit_width / 7];
        overflow.push(1 << (bit_width % 7));
        assert_error::<T>(&overflow, Error::InvalidVarint);
    }

    macro_rules! test_types {
        ($($ty:ident),* $(,)?) => {
            $(
                #[test]
                fn $ty() {
                    test_type::<$ty>(<$ty>::MAX);
                }
            )*
        };
    }

    test_types!(u8, u16, u32, u64, usize);
}
