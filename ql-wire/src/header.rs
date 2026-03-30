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
    pub const ENCODED_LEN: usize = ConnectionId::SIZE + core::mem::size_of::<u64>();

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        codec::push_bytes(out, self.connection_id.as_bytes());
        codec::push_u64(out, self.seq.0);
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
        let mut aad = Vec::new();
        codec::append_field(&mut aad, b"domain", b"ql-wire:session-aad:v1");
        codec::append_field(&mut aad, b"wire-version", &[QL_WIRE_VERSION]);
        codec::append_field(&mut aad, b"record-kind", b"session");
        codec::append_field(&mut aad, b"connection-id", self.connection_id.as_bytes());
        codec::append_field(&mut aad, b"record-seq", &self.seq.0.to_le_bytes());
        aad
    }
}
