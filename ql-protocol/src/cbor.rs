use dcbor::CBOR;

pub fn cbor_array<const N: usize>(array: Vec<CBOR>) -> dcbor::Result<[CBOR; N]> {
    if array.len() != N {
        return Err(dcbor::Error::msg("invalid array length"));
    }
    array
        .try_into()
        .map_err(|_| dcbor::Error::msg("invalid array length"))
}

pub fn option_to_cbor<T>(value: Option<T>) -> CBOR
where
    T: Into<CBOR>,
{
    value.map(Into::into).unwrap_or_else(CBOR::null)
}

pub fn option_from_cbor<T>(value: CBOR) -> dcbor::Result<Option<T>>
where
    T: TryFrom<CBOR, Error = dcbor::Error>,
{
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(value.try_into()?))
    }
}
