use crate::{codec, ByteSlice, VarInt, VarIntBoundsExceeded, QL_WIRE_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionHeader {
    pub connection_id: ConnectionId,
    pub seq: RecordSeq,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RecordSeq(pub VarInt);

impl RecordSeq {
    pub const MAX_ENCODED_LEN: usize = VarInt::MAX_SIZE;

    pub const fn from_u32(value: u32) -> Self {
        Self(VarInt::from_u32(value))
    }

    pub fn from_u64(value: u64) -> Result<Self, VarIntBoundsExceeded> {
        Ok(Self(VarInt::from_u64(value)?))
    }

    pub const fn into_inner(self) -> u64 {
        self.0.into_inner()
    }

    pub const fn encoded_len(self) -> usize {
        self.0.size()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ConnectionId(pub [u8; Self::SIZE]);

impl ConnectionId {
    pub const SIZE: usize = 16;

    pub const fn from_data(data: [u8; Self::SIZE]) -> Self {
        Self(data)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }
}

impl SessionHeader {
    pub const MAX_ENCODED_LEN: usize = ConnectionId::SIZE + RecordSeq::MAX_ENCODED_LEN;
    const AAD_DOMAIN: &[u8] = b"ql-wire:session-aad:v1";
    const AAD_RECORD_KIND_SESSION: u8 = 1;

    pub fn encoded_len(&self) -> usize {
        ConnectionId::SIZE + self.seq.encoded_len()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0; self.encoded_len()];
        let _ = self.encode_into(&mut out);
        out
    }

    pub fn encode_into<'a>(&self, out: &'a mut [u8]) -> &'a mut [u8] {
        assert!(out.len() >= self.encoded_len());
        let out = codec::write_bytes(out, self.connection_id.as_bytes());
        codec::write_varint(out, self.seq.0)
    }

    pub fn aad(&self) -> Vec<u8> {
        let aad_len = Self::AAD_DOMAIN.len()
            + size_of::<u8>()
            + size_of::<u8>()
            + ConnectionId::SIZE
            + self.seq.encoded_len();
        let mut aad = vec![0; aad_len];
        let out = codec::write_bytes(&mut aad, Self::AAD_DOMAIN);
        let out = codec::write_u8(out, QL_WIRE_VERSION);
        let out = codec::write_u8(out, Self::AAD_RECORD_KIND_SESSION);
        let out = codec::write_bytes(out, self.connection_id.as_bytes());
        let _ = codec::write_varint(out, self.seq.0);
        aad
    }
}

impl<B: ByteSlice> codec::WireParse<B> for SessionHeader {
    fn parse(reader: &mut codec::Reader<B>) -> Result<Self, crate::WireError> {
        Ok(Self {
            connection_id: ConnectionId::from_data(reader.take_array()?),
            seq: RecordSeq(reader.take_varint()?),
        })
    }
}
