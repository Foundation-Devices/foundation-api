use std::io;

use bytes::{Buf, BufMut};
use serde::{de::DeserializeOwned, Serialize};

use crate::Error;

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
