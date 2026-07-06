use core::fmt;

/// An integer less than 2^62 encoded with QUIC variable-length integer rules.
#[derive(Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VarInt(u64);

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
    pub const fn from_u64(x: u64) -> Result<Self, VarIntBoundsExceeded> {
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

    /// Return the encoded length from the first encoded byte.
    pub const fn encoded_len_from_first_byte(first: u8) -> usize {
        1usize << (first >> 6)
    }

    /// Encode this value by writing its encoded bytes to `write`.
    #[allow(clippy::cast_possible_truncation)]
    pub fn write_bytes(self, mut write: impl FnMut(&[u8])) {
        let value = self.0;
        match self.size() {
            1 => write(&[value as u8]),
            2 => write(&((value as u16) | 0x4000).to_be_bytes()),
            4 => write(&((value as u32) | 0x8000_0000).to_be_bytes()),
            8 => write(&(value | 0xC000_0000_0000_0000).to_be_bytes()),
            _ => unreachable!(),
        }
    }

    /// decode a value from the start of `bytes`, returning the value and remaining bytes
    pub fn decode_bytes(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let first = *bytes.first()?;
        let len = Self::encoded_len_from_first_byte(first);
        Some((
            Self::decode_with_first_byte(first, bytes.get(1..len)?)?,
            &bytes[len..],
        ))
    }

    /// decode a value after the first encoded byte has already been consumed
    pub fn decode_with_first_byte(first: u8, tail: &[u8]) -> Option<Self> {
        let len = Self::encoded_len_from_first_byte(first);
        if tail.len() != len - 1 {
            return None;
        }
        let value = match len {
            1 => u64::from(first & 0x3f),
            2 => u64::from(u16::from_be_bytes([first & 0x3f, tail[0]])),
            4 => {
                let bytes = [first & 0x3f, tail[0], tail[1], tail[2]];
                u64::from(u32::from_be_bytes(bytes))
            }
            8 => {
                let bytes = [
                    first & 0x3f,
                    tail[0],
                    tail[1],
                    tail[2],
                    tail[3],
                    tail[4],
                    tail[5],
                    tail[6],
                ];
                u64::from_be_bytes(bytes)
            }
            _ => unreachable!(),
        };
        Self::from_u64(value).ok()
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

#[macro_export]
macro_rules! varint_wrapper {
    ($(#[$attr:meta])* $name:ident $(,)?) => {
        $(#[$attr])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $name(pub $crate::VarInt);

        impl $name {
            pub const MAX_ENCODED_LEN: usize = $crate::VarInt::MAX_SIZE;

            pub const fn from_u32(value: u32) -> Self {
                Self($crate::VarInt::from_u32(value))
            }

            pub const fn from_u64(value: u64) -> Result<Self, $crate::VarIntBoundsExceeded> {
                match $crate::VarInt::from_u64(value) {
                    Ok(v) => Ok(Self(v)),
                    Err(e) => Err(e),
                }
            }

            /// Create this wrapper without checking the bounds.
            ///
            /// # Safety
            ///
            /// `value` must be less than 2^62.
            pub const unsafe fn from_u64_unchecked(value: u64) -> Self {
                Self(unsafe { $crate::VarInt::from_u64_unchecked(value) })
            }
        }

        impl From<$crate::VarInt> for $name {
            fn from(value: $crate::VarInt) -> Self {
                Self(value)
            }
        }

        impl From<u32> for $name {
            fn from(value: u32) -> Self {
                Self::from_u32(value)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}
