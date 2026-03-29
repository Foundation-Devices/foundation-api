use crate::{codec, QL_WIRE_VERSION, XID};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeHeader {
    pub sender: XID,
    pub recipient: XID,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionHeader {
    pub connection_id: ConnectionId,
}

impl HandshakeHeader {
    pub const ENCODED_LEN: usize = XID::SIZE * 2;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        codec::push_bytes(out, &self.sender.0);
        codec::push_bytes(out, &self.recipient.0);
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
            sender: XID(reader.take_array()?),
            recipient: XID(reader.take_array()?),
        })
    }
}

impl SessionHeader {
    pub const ENCODED_LEN: usize = ConnectionId::SIZE;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        codec::push_bytes(out, self.connection_id.as_bytes());
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
        })
    }

    pub fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::new();
        codec::append_field(&mut aad, b"domain", b"ql-wire:session-aad:v1");
        codec::append_field(&mut aad, b"wire-version", &[QL_WIRE_VERSION]);
        codec::append_field(&mut aad, b"record-kind", b"session");
        codec::append_field(&mut aad, b"connection-id", self.connection_id.as_bytes());
        aad
    }
}
