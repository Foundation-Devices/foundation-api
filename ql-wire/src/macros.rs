macro_rules! varint_wrapper_codec {
    ($name:ty) => {
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
                Ok(<$name>::from(reader.decode::<$crate::VarInt>()?))
            }
        }
    };
}

macro_rules! array_wrapper_codec {
    ($name:ty) => {
        impl $crate::WireEncode for $name {
            fn encoded_len(&self) -> usize {
                <$name>::SIZE
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
