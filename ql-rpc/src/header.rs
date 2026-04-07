use bytes::{Buf, BufMut};

use crate::{MethodId, RpcCodec, RpcError, RPC_VERSION};

const HEADER_SIZE: usize = 1 + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcHeader {
    pub version: u8,
    pub method: MethodId,
}

impl RpcHeader {
    pub const WIRE_SIZE: usize = HEADER_SIZE;

    pub const fn new(method: MethodId) -> Self {
        Self {
            version: RPC_VERSION,
            method,
        }
    }
}

impl RpcCodec for RpcHeader {
    type Error = RpcError;

    fn encode_value<B: BufMut + ?Sized>(&self, out: &mut B) -> Result<(), Self::Error> {
        out.put_u8(self.version);
        out.put_u64_le(self.method.0);
        Ok(())
    }

    fn decode_value<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error> {
        let version = bytes.try_get_u8().map_err(|_| RpcError::Truncated)?;
        if version != RPC_VERSION {
            return Err(RpcError::InvalidVersion(version));
        }

        let method = MethodId(bytes.try_get_u64_le().map_err(|_| RpcError::Truncated)?);
        Ok(Self { version, method })
    }
}
