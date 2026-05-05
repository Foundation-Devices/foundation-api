use std::io;

use bytes::{Buf, BufMut};
use serde::{de::DeserializeOwned, Serialize};

use crate::Error;

macro_rules! impl_codec {
    ($ty:ty) => {
        impl ql_rpc::RpcCodec for $ty {
            type Error = crate::Error;

            fn encode_value<B: bytes::BufMut + ?Sized>(&self, out: &mut B) {
                $crate::codec::encode_cbor(self, out);
            }

            fn decode_value<B: bytes::Buf>(bytes: &mut B) -> Result<Self, Self::Error> {
                $crate::codec::decode_cbor(bytes)
            }
        }
    };
}

pub(crate) use impl_codec;

macro_rules! rpc {
    ($(#[$attr:meta])* $vis:vis struct $name:ident;) => {
        compile_error!("rpc! does not support unit structs");
    };
    ($(#[$attr:meta])* $vis:vis struct $name:ident $($body:tt)+) => {
        #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        $(#[$attr])*
        #[cfg_attr(feature = "frb", flutter_rust_bridge::frb(non_opaque))]
        $vis struct $name $($body)+

        $crate::codec::impl_codec!($name);
    };
}

pub(crate) use rpc;

pub fn encode_cbor<T, B>(value: &T, out: &mut B)
where
    T: Serialize,
    B: BufMut + ?Sized,
{
    ciborium::ser::into_writer(value, BufMutWriter(out))
        .expect("CBOR serialization to BufMut failed");
}

pub fn decode_cbor<T, B>(bytes: &mut B) -> Result<T, Error>
where
    T: DeserializeOwned,
    B: Buf,
{
    let value = ciborium::de::from_reader(BufReader(bytes))?;
    bytes.advance(bytes.remaining());
    Ok(value)
}

struct BufMutWriter<'a, B: BufMut + ?Sized>(&'a mut B);

impl<B: BufMut + ?Sized> io::Write for BufMutWriter<'_, B> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.0.remaining_mut() < data.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }

        self.0.put_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct BufReader<'a, B: Buf>(&'a mut B);

impl<B: Buf> io::Read for BufReader<'_, B> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let len = out.len().min(self.0.remaining());
        if len == 0 {
            return Ok(0);
        }

        self.0.copy_to_slice(&mut out[..len]);
        Ok(len)
    }
}
