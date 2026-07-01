use bytes::BufMut;
use ql_common::VarInt;

use crate::{ByteSlice, Reader, WireDecode, WireEncode, WireError};

impl<B: ByteSlice> WireDecode<B> for ql_common::VarInt {
    fn decode(reader: &mut Reader<B>) -> Result<Self, WireError> {
        let first = reader.decode::<u8>()?;
        let len = VarInt::encoded_len_from_first_byte(first);
        let tail = reader.take_bytes(len - 1)?;
        VarInt::decode_with_first_byte(first, &tail).ok_or(WireError::InvalidPayload)
    }
}

impl WireEncode for ql_common::VarInt {
    fn encoded_len(&self) -> usize {
        self.size()
    }

    fn encode<W: BufMut + ?Sized>(&self, out: &mut W) {
        self.write_bytes(|bytes| out.put_slice(bytes));
    }
}
