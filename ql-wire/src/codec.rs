use zerocopy::{
    byteorder::little_endian::{U16, U32, U64},
    FromBytes, Immutable, IntoBytes, KnownLayout, Ref,
};

use crate::{QlHeader, WireError};

pub(crate) type U16Le = U16;
pub(crate) type U32Le = U32;
pub(crate) type U64Le = U64;

pub(crate) fn push_value<T>(out: &mut Vec<u8>, value: &T)
where
    T: IntoBytes + Immutable + ?Sized,
{
    out.extend_from_slice(value.as_bytes());
}

pub(crate) fn read_exact<T>(bytes: &[u8]) -> Result<T, WireError>
where
    T: FromBytes + Copy,
{
    T::read_from_bytes(bytes).map_err(|_| WireError::InvalidPayload)
}

pub(crate) fn read_prefix<T>(bytes: &[u8]) -> Result<(T, &[u8]), WireError>
where
    T: FromBytes + KnownLayout + Immutable + Copy,
{
    let (value, rest) = Ref::<_, T>::from_prefix(bytes).map_err(|_| WireError::InvalidPayload)?;
    Ok((*value, rest))
}

pub(crate) fn read_prefix_mut<'a, T>(bytes: &'a mut [u8]) -> Result<(T, &'a mut [u8]), WireError>
where
    T: FromBytes + KnownLayout + Immutable + Copy,
{
    let (value, rest) = Ref::<_, T>::from_prefix(bytes).map_err(|_| WireError::InvalidPayload)?;
    Ok((*value, rest))
}

pub(crate) fn ensure_empty(bytes: &[u8]) -> Result<(), WireError> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(WireError::InvalidPayload)
    }
}

pub(crate) fn append_field(out: &mut Vec<u8>, label: &[u8], value: &[u8]) {
    append_framed_bytes(out, label);
    append_framed_bytes(out, value);
}

pub(crate) fn append_framed_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u64::try_from(value.len()).unwrap().to_le_bytes());
    out.extend_from_slice(value);
}

pub(crate) fn header_aad(header: &QlHeader) -> Vec<u8> {
    let mut aad = Vec::new();
    append_field(&mut aad, b"domain", b"ql-wire:header-aad:v1");
    append_field(&mut aad, b"sender", &header.sender);
    append_field(&mut aad, b"recipient", &header.recipient);
    aad
}
