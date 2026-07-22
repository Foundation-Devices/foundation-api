//! Small binary codec primitives shared by QuantumLink crates.

mod buf_view;
mod codec;
mod error;
mod reader;
mod slice;
pub mod varint;

pub use buf_view::BufView;
pub use codec::{encode_bytes, encoded_len_bytes};
pub use error::Error;
pub use reader::Reader;
pub use slice::ByteSlice;
pub use varint::Varint;

pub trait Encode {
    fn encoded_len(&self) -> usize;

    fn encode<W: bytes::BufMut + ?Sized>(&self, out: &mut W);

    fn encode_vec(&self) -> Vec<u8> {
        let len = self.encoded_len();
        let mut out = Vec::with_capacity(len);
        self.encode(&mut out);
        assert_eq!(out.len(), len);
        out
    }
}

pub trait Decode<B: ByteSlice>: Sized {
    fn decode(reader: &mut Reader<B>) -> Result<Self, Error>;

    fn decode_bytes(bytes: B) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        Self::decode(&mut reader)
    }
}

#[macro_export]
macro_rules! varint_wrapper {
    ($name:ty, $inner:ty) => {
        impl $name {
            pub const MAX_ENCODED_LEN: usize =
                <$inner as ql_codec::varint::Primitive>::MAX_ENCODED_LEN;
        }

        impl ql_codec::Encode for $name {
            fn encoded_len(&self) -> usize {
                ql_codec::varint::encoded_len::<$inner>(self.0)
            }

            fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
                ql_codec::varint::encode::<$inner, W>(self.0, out);
            }
        }

        impl<B: ql_codec::ByteSlice> ql_codec::Decode<B> for $name {
            fn decode(reader: &mut ql_codec::Reader<B>) -> Result<Self, ql_codec::Error> {
                Ok(Self(reader.decode_varint::<$inner>()?))
            }
        }
    };
}
