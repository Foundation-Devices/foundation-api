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

        impl ql_codec::Encode for $name {
            fn encoded_len(&self) -> usize {
                Self::SIZE
            }

            fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
                self.0.encode(out);
            }
        }

        impl<B: ql_codec::ByteSlice> ql_codec::Decode<B> for $name {
            fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, ql_codec::Error> {
                Ok(Self(reader.decode()?))
            }
        }
    };
}
