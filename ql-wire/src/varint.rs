use bytes::BufMut;

use crate::{ByteSlice, Reader, WireDecode, WireEncode, WireError};

impl<B: ByteSlice> WireDecode<B> for ql_common::VarInt {
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

impl WireEncode for ql_common::VarInt {
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
