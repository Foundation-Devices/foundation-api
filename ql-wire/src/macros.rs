macro_rules! varint_wrapper {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $name(pub $crate::VarInt);

        impl $name {
            pub const MAX_ENCODED_LEN: usize = $crate::VarInt::MAX_SIZE;

            pub const fn from_u32(value: u32) -> Self {
                Self($crate::VarInt::from_u32(value))
            }

            pub fn from_u64(value: u64) -> Result<Self, $crate::VarIntBoundsExceeded> {
                Ok(Self($crate::VarInt::from_u64(value)?))
            }

            pub const fn into_inner(self) -> u64 {
                self.0.into_inner()
            }
        }

        impl $crate::WireEncode for $name {
            fn encoded_len(&self) -> usize {
                self.0.size()
            }

            fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
                self.0.encode(out);
            }
        }

        impl<B: $crate::ByteSlice> $crate::WireDecode<B> for $name {
            fn decode(reader: &mut $crate::Reader<B>) -> Result<Self, $crate::WireError> {
                Ok(Self(reader.decode()?))
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

macro_rules! array_wrapper {
    ($name:ident, $size:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(transparent)]
        pub struct $name(pub [u8; Self::SIZE]);

        impl $name {
            pub const SIZE: usize = $size;

            pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
                &self.0
            }
        }

        impl $crate::WireEncode for $name {
            fn encoded_len(&self) -> usize {
                Self::SIZE
            }

            fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
                self.0.encode(out);
            }
        }

        impl<B: $crate::ByteSlice> $crate::codec::WireDecode<B> for $name {
            fn decode(reader: &mut $crate::codec::Reader<B>) -> Result<Self, $crate::WireError> {
                Ok(Self(reader.decode()?))
            }
        }
    };
}

pub(crate) use array_wrapper;
pub(crate) use varint_wrapper;
