use std::io;

use bytes::{Buf, BufMut};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::Error;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "frb", flutter_rust_bridge::frb(non_opaque))]
pub struct Empty {}

impl ql_rpc::RpcCodec for Empty {
    type Error = Error;

    fn encode_value<B: BufMut + ?Sized>(&self, out: &mut B) {
        encode_cbor(&self, out);
    }

    fn decode_value<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error> {
        decode_cbor::<Self, _>(bytes)?;
        Ok(Self {})
    }
}

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

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct OldHeader {}

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct NewHeader {
        field: Option<u32>,
    }

    #[test]
    fn cbor_empty_struct_can_evolve_with_optional_fields() {
        let mut old_bytes = BytesMut::new();
        encode_cbor(&OldHeader {}, &mut old_bytes);

        let decoded_new: NewHeader = decode_cbor(&mut old_bytes.freeze()).unwrap();
        assert_eq!(decoded_new, NewHeader { field: None });

        let mut new_bytes = BytesMut::new();
        encode_cbor(&NewHeader { field: Some(7) }, &mut new_bytes);

        let decoded_old: OldHeader = decode_cbor(&mut new_bytes.freeze()).unwrap();
        assert_eq!(decoded_old, OldHeader {});
    }

    #[test]
    fn empty_codec_can_evolve_into_cbor_fields() {
        let mut empty_bytes = BytesMut::new();
        ql_rpc::RpcCodec::encode_value(&Empty {}, &mut empty_bytes);
        assert!(!empty_bytes.is_empty());

        let decoded_new: NewHeader = decode_cbor(&mut empty_bytes.freeze()).unwrap();
        assert_eq!(decoded_new, NewHeader { field: None });

        let mut new_bytes = BytesMut::new();
        encode_cbor(&NewHeader { field: Some(7) }, &mut new_bytes);

        let decoded_empty =
            <Empty as ql_rpc::RpcCodec>::decode_value(&mut new_bytes.freeze()).unwrap();
        assert_eq!(decoded_empty, Empty {});
    }
}
