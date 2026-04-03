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
    pub const ENCODED_LEN: usize = size_of::<u32>() + size_of::<u64>();

    pub fn ensure_not_expired(&self, now_seconds: u64) -> Result<(), WireError> {
        if now_seconds > self.valid_until {
            Err(WireError::Expired)
        } else {
            Ok(())
        }
    }

    pub fn encode_into<'a>(&self, out: &'a mut [u8]) -> &'a mut [u8] {
        let out = codec::write_u32(out, self.handshake_id.0);
        codec::write_u64(out, self.valid_until)
    }

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0; Self::ENCODED_LEN];
        let _ = self.encode_into(&mut out);
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
