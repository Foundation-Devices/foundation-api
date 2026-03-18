use zerocopy::{
    byte_slice::{ByteSlice, SplitByteSlice},
    byteorder::little_endian,
    FromBytes, Immutable, IntoBytes, KnownLayout, Ref, TryFromBytes,
};

use crate::{QlHeader, WireError};

pub type U16Le = little_endian::U16;
pub type U32Le = little_endian::U32;
pub type U64Le = little_endian::U64;

pub fn push_value<T>(out: &mut Vec<u8>, value: &T)
where
    T: IntoBytes + Immutable + ?Sized,
{
    out.extend_from_slice(value.as_bytes());
}

pub fn read_exact<T>(bytes: &[u8]) -> Result<T, WireError>
where
    T: FromBytes + Copy,
{
    T::read_from_bytes(bytes).map_err(|_| WireError::InvalidPayload)
}

pub fn read_byte<T>(byte: u8) -> Result<T, WireError>
where
    T: TryFromBytes + Copy,
{
    T::try_read_from_bytes(core::slice::from_ref(&byte)).map_err(|_| WireError::InvalidPayload)
}

pub fn read_prefix<T, B>(bytes: B) -> Result<(T, B), WireError>
where
    B: SplitByteSlice,
    T: FromBytes + KnownLayout + Immutable + Copy,
{
    let (value, rest) = Ref::<_, T>::from_prefix(bytes).map_err(|_| WireError::InvalidPayload)?;
    Ok((*value, rest))
}

pub fn parse<T, B>(bytes: B) -> Result<Ref<B, T>, WireError>
where
    B: ByteSlice,
    T: KnownLayout + Immutable + ?Sized,
{
    Ref::<_, T>::from_bytes(bytes).map_err(|_| WireError::InvalidPayload)
}

pub fn ensure_empty(bytes: &[u8]) -> Result<(), WireError> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(WireError::InvalidPayload)
    }
}

pub fn append_field(out: &mut Vec<u8>, label: &[u8], value: &[u8]) {
    append_framed_bytes(out, label);
    append_framed_bytes(out, value);
}

pub fn append_framed_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u64::try_from(value.len()).unwrap().to_le_bytes());
    out.extend_from_slice(value);
}

pub fn header_aad(header: &QlHeader) -> Vec<u8> {
    let mut aad = Vec::new();
    append_field(&mut aad, b"domain", b"ql-wire:header-aad:v1");
    append_field(&mut aad, b"sender", &header.sender.0);
    append_field(&mut aad, b"recipient", &header.recipient.0);
    aad
}
