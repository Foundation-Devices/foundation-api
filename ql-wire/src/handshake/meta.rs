use crate::{codec, ByteSlice, WireEncode, WireError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct HandshakeId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeMeta {
    pub handshake_id: HandshakeId,
    pub valid_until: u64,
}

impl<B: ByteSlice> codec::WireDecode<B> for HandshakeId {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self(reader.decode()?))
    }
}

impl WireEncode for HandshakeId {
    fn encoded_len(&self) -> usize {
        size_of::<u32>()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
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
}

impl WireEncode for HandshakeMeta {
    fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.handshake_id.encode(out);
        self.valid_until.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for HandshakeMeta {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            handshake_id: reader.decode()?,
            valid_until: reader.decode()?,
        })
    }
}
