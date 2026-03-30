use crate::{codec, WireError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct HandshakeId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeMeta {
    pub handshake_id: HandshakeId,
    pub valid_until: u64,
}

impl HandshakeMeta {
    pub const ENCODED_LEN: usize = core::mem::size_of::<u32>() + core::mem::size_of::<u64>();

    pub fn ensure_not_expired(&self, now_seconds: u64) -> Result<(), WireError> {
        if now_seconds > self.valid_until {
            Err(WireError::Expired)
        } else {
            Ok(())
        }
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        codec::push_u32(out, self.handshake_id.0);
        codec::push_u64(out, self.valid_until);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        self.encode_into(&mut out);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        let meta = Self {
            handshake_id: HandshakeId(reader.take_u32()?),
            valid_until: reader.take_u64()?,
        };
        reader.finish()?;
        Ok(meta)
    }

    pub fn decode_from<B: crate::ByteSlice>(
        reader: &mut codec::Reader<B>,
    ) -> Result<Self, WireError> {
        Ok(Self {
            handshake_id: HandshakeId(reader.take_u32()?),
            valid_until: reader.take_u64()?,
        })
    }
}
