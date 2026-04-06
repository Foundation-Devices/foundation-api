use crate::{codec, ByteSlice, WireError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct HandshakeId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeMeta {
    pub handshake_id: HandshakeId,
    pub valid_until: u64,
}

impl<B: ByteSlice> codec::WireParse<B> for HandshakeId {
    fn parse(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self(reader.parse()?))
    }
}

impl HandshakeMeta {
    pub const WIRE_SIZE: usize = size_of::<u32>() + size_of::<u64>();

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

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut out = [0; Self::WIRE_SIZE];
        let _ = self.encode_into(&mut out);
        out
    }
}

impl<B: ByteSlice> codec::WireParse<B> for HandshakeMeta {
    fn parse(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            handshake_id: reader.parse()?,
            valid_until: reader.parse()?,
        })
    }
}
