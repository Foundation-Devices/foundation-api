use core::fmt;

use bytes::BufMut;

use crate::{ByteSlice, Reader, WireDecode, WireEncode, WireError};

/// An integer less than 2^62 encoded with QUIC variable-length integer rules.
#[derive(Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VarInt(pub(crate) u64);

impl VarInt {
    /// The largest representable value.
    pub const MAX: Self = Self((1u64 << 62) - 1);
    /// The largest encoded value length.
    pub const MAX_SIZE: usize = 8;
    pub const MIN_SIZE: usize = 1;

    /// Construct a `VarInt` infallibly from a `u32`.
    pub const fn from_u32(x: u32) -> Self {
        Self(x as u64)
    }

    /// Construct a `VarInt` from a `u64`.
    pub fn from_u64(x: u64) -> Result<Self, VarIntBoundsExceeded> {
        if x < (1u64 << 62) {
            Ok(Self(x))
        } else {
            Err(VarIntBoundsExceeded)
        }
    }

    /// Create a `VarInt` without checking the bounds.
    ///
    /// # Safety
    ///
    /// `x` must be less than 2^62.
    pub const unsafe fn from_u64_unchecked(x: u64) -> Self {
        Self(x)
    }

    /// Extract the inner integer value.
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// Return the number of bytes required to encode this value.
    pub const fn size(self) -> usize {
        let x = self.0;
        if x < (1u64 << 6) {
            1
        } else if x < (1u64 << 14) {
            2
        } else if x < (1u64 << 30) {
            4
        } else {
            8
        }
    }
}

impl From<VarInt> for u64 {
    fn from(value: VarInt) -> Self {
        value.0
    }
}

impl From<u8> for VarInt {
    fn from(value: u8) -> Self {
        Self(value.into())
    }
}

impl From<u16> for VarInt {
    fn from(value: u16) -> Self {
        Self(value.into())
    }
}

impl From<u32> for VarInt {
    fn from(value: u32) -> Self {
        Self(value.into())
    }
}

impl TryFrom<u64> for VarInt {
    type Error = VarIntBoundsExceeded;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::from_u64(value)
    }
}

impl TryFrom<u128> for VarInt {
    type Error = VarIntBoundsExceeded;

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        Self::from_u64(value.try_into().map_err(|_| VarIntBoundsExceeded)?)
    }
}

impl TryFrom<usize> for VarInt {
    type Error = VarIntBoundsExceeded;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::from_u64(value as u64)
    }
}

impl fmt::Debug for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct VarIntBoundsExceeded;

impl fmt::Display for VarIntBoundsExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("value too large for varint encoding")
    }
}

impl std::error::Error for VarIntBoundsExceeded {}

impl<B: ByteSlice> WireDecode<B> for VarInt {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        let first = reader.decode::<u8>()?;
        let tag = first >> 6;
        let first = first & 0b0011_1111;
        let value = match tag {
            0b00 => u64::from(first),
            0b01 => {
                let mut buf = [0; 2];
                buf[0] = first;
                buf[1] = reader.decode()?;
                u64::from(u16::from_be_bytes(buf))
            }
            0b10 => {
                let mut buf = [0; 4];
                buf[0] = first;
                buf[1..].copy_from_slice(&reader.take_bytes(3)?);
                u64::from(u32::from_be_bytes(buf))
            }
            0b11 => {
                let mut buf = [0; 8];
                buf[0] = first;
                buf[1..].copy_from_slice(&reader.take_bytes(7)?);
                u64::from_be_bytes(buf)
            }
            _ => unreachable!(),
        };

        // SAFETY: the decoded value is guaranteed to fit in the 62-bit varint range.
        Ok(unsafe { Self::from_u64_unchecked(value) })
    }
}

impl WireEncode for VarInt {
    fn encoded_len(&self) -> usize {
        self.size()
    }

    #[allow(clippy::cast_possible_truncation)]
    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        let x = self.into_inner();
        match self.size() {
            1 => out.put_u8(x as u8),
            2 => out.put_u16((0b01 << 14) | x as u16),
            4 => out.put_u32((0b10 << 30) | x as u32),
            8 => out.put_u64((0b11 << 62) | x),
            _ => unreachable!("malformed varint"),
        }
    }
}
