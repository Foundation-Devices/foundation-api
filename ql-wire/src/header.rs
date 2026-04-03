use crate::{codec, QL_WIRE_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionHeader {
    pub connection_id: ConnectionId,
    pub seq: RecordSeq,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RecordSeq(pub u64);

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
    pub const ENCODED_LEN: usize = ConnectionId::SIZE + size_of::<u64>();
    const AAD_DOMAIN: &[u8] = b"ql-wire:session-aad:v1";
    const AAD_RECORD_KIND_SESSION: u8 = 1;

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0; Self::ENCODED_LEN];
        self.encode_into(&mut out);
        out
    }

    pub fn encode_into(&self, out: &mut [u8]) {
        assert_eq!(out.len(), Self::ENCODED_LEN);
        let out = codec::write_bytes(out, self.connection_id.as_bytes());
        let _ = codec::write_u64(out, self.seq.0);
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, crate::WireError> {
        let mut reader = codec::Reader::new(bytes);
        let header = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(header)
    }

    pub fn decode_from<B: crate::ByteSlice>(
        reader: &mut codec::Reader<B>,
    ) -> Result<Self, crate::WireError> {
        Ok(Self {
            connection_id: ConnectionId::from_data(reader.take_array()?),
            seq: RecordSeq(reader.take_u64()?),
        })
    }

    pub fn aad(&self) -> Vec<u8> {
        let aad_len = Self::AAD_DOMAIN.len()
            + size_of::<u8>()
            + size_of::<u8>()
            + ConnectionId::SIZE
            + size_of::<RecordSeq>();
        let mut aad = vec![0; aad_len];
        let out = codec::write_bytes(&mut aad, Self::AAD_DOMAIN);
        let out = codec::write_u8(out, QL_WIRE_VERSION);
        let out = codec::write_u8(out, Self::AAD_RECORD_KIND_SESSION);
        let out = codec::write_bytes(out, self.connection_id.as_bytes());
        let _ = codec::write_u64(out, self.seq.0);
        aad
    }
}
