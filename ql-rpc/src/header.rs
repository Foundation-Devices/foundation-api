use crate::{MethodId, RpcError, RPC_VERSION};

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

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.version);
        out.extend_from_slice(&self.method.0.to_le_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), RpcError> {
        if bytes.len() < Self::WIRE_SIZE {
            return Err(RpcError::Truncated);
        }

        let version = bytes[0];
        if version != RPC_VERSION {
            return Err(RpcError::InvalidVersion(version));
        }

        let method = MethodId(u64::from_le_bytes(
            bytes[1..Self::WIRE_SIZE].try_into().unwrap(),
        ));
        Ok((Self { version, method }, &bytes[Self::WIRE_SIZE..]))
    }
}
