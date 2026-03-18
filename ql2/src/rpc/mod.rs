mod server;

pub mod client;
pub mod modality;

pub use client::RpcHandle;
use dcbor::CBOR;
pub use modality::{MethodId, QlCodec, RequestResponse};

use crate::QlError;

pub(crate) const RPC_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcRequestHead {
    pub version: u16,
    pub method: MethodId,
    pub content_length: Option<u64>,
}

impl RpcRequestHead {
    pub fn new(method: MethodId, content_length: Option<u64>) -> Self {
        Self {
            version: RPC_VERSION,
            method,
            content_length,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcResponseHead {
    pub version: u16,
    pub content_length: Option<u64>,
}

impl RpcResponseHead {
    pub fn new(content_length: Option<u64>) -> Self {
        Self {
            version: RPC_VERSION,
            content_length,
        }
    }
}

impl Default for RpcResponseHead {
    fn default() -> Self {
        Self::new(None)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error(transparent)]
    Transport(#[from] QlError),
    #[error(transparent)]
    Decode(#[from] dcbor::Error),
    #[error("unsupported rpc version {0}")]
    BadVersion(u16),
    #[error("rpc content length mismatch: expected {expected}, got {actual}")]
    ContentLengthMismatch { expected: u64, actual: u64 },
}

impl From<RpcRequestHead> for CBOR {
    fn from(value: RpcRequestHead) -> Self {
        CBOR::from(vec![
            CBOR::from(value.version),
            CBOR::from(value.method),
            value
                .content_length
                .map(CBOR::from)
                .unwrap_or_else(CBOR::null),
        ])
    }
}

impl TryFrom<CBOR> for RpcRequestHead {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let [version, method, content_length] = take_fields(value.try_into_array()?.into_iter())?;
        Ok(Self {
            version: version.try_into()?,
            method: method.try_into()?,
            content_length: if content_length.is_null() {
                None
            } else {
                Some(content_length.try_into()?)
            },
        })
    }
}

impl From<RpcResponseHead> for CBOR {
    fn from(value: RpcResponseHead) -> Self {
        CBOR::from(vec![
            CBOR::from(value.version),
            value
                .content_length
                .map(CBOR::from)
                .unwrap_or_else(CBOR::null),
        ])
    }
}

impl TryFrom<CBOR> for RpcResponseHead {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        let [version, content_length] = take_fields(value.try_into_array()?.into_iter())?;
        Ok(Self {
            version: version.try_into()?,
            content_length: if content_length.is_null() {
                None
            } else {
                Some(content_length.try_into()?)
            },
        })
    }
}

fn take_fields<const N: usize>(
    mut iter: impl Iterator<Item = CBOR>,
) -> Result<[CBOR; N], dcbor::Error> {
    use std::mem::MaybeUninit;

    let mut fields: [MaybeUninit<CBOR>; N] = [const { MaybeUninit::uninit() }; N];
    for (index, slot) in fields.iter_mut().enumerate() {
        let Some(value) = iter.next() else {
            for init in &mut fields[..index] {
                unsafe { init.assume_init_drop() };
            }
            return Err(dcbor::Error::msg("array too short"));
        };
        slot.write(value);
    }
    let result = unsafe { std::ptr::read(&fields as *const _ as *const [CBOR; N]) };
    if iter.next().is_some() {
        return Err(dcbor::Error::msg("array too long"));
    }
    Ok(result)
}

#[test]
fn take_fields_reads_exact_count() {
    let values = vec![CBOR::from(1u8), CBOR::from(2u8), CBOR::from(3u8)];
    let mut iter = values.into_iter();
    let [first, second, third] = take_fields(&mut iter).unwrap();
    assert_eq!(u8::try_from(first).unwrap(), 1);
    assert_eq!(u8::try_from(second).unwrap(), 2);
    assert_eq!(u8::try_from(third).unwrap(), 3);
    assert!(iter.next().is_none());
}
