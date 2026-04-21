use ::bytes::BufMut;

use crate::{
    codec, ByteSlice, VarInt, VarIntBoundsExceeded, WireEncode, WireError, QL_WIRE_VERSION,
};

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

impl<B: ByteSlice> codec::WireDecode<B> for RecordSeq {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self(reader.decode()?))
    }
}

impl WireEncode for RecordSeq {
    fn encoded_len(&self) -> usize {
        self.0.size()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for ConnectionId {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self::from_data(reader.decode()?))
    }
}

impl WireEncode for ConnectionId {
    fn encoded_len(&self) -> usize {
        Self::SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}

impl SessionHeader {
    pub const MAX_ENCODED_LEN: usize = ConnectionId::SIZE + RecordSeq::MAX_ENCODED_LEN;
    const AAD_DOMAIN: &[u8] = b"ql-wire:session-aad:v1";
    const AAD_RECORD_KIND_SESSION: u8 = 1;

    pub fn aad(&self) -> Vec<u8> {
        let aad_len = Self::AAD_DOMAIN.len()
            + size_of::<u8>()
            + size_of::<u8>()
            + ConnectionId::SIZE
            + self.seq.encoded_len();
        let mut aad = Vec::with_capacity(aad_len);
        aad.put_slice(Self::AAD_DOMAIN);
        aad.put_u8(QL_WIRE_VERSION);
        aad.put_u8(Self::AAD_RECORD_KIND_SESSION);
        self.connection_id.encode(&mut aad);
        self.seq.encode(&mut aad);
        debug_assert_eq!(aad.len(), aad_len);
        aad
    }
}

impl WireEncode for SessionHeader {
    fn encoded_len(&self) -> usize {
        ConnectionId::SIZE + self.seq.encoded_len()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.connection_id.encode(out);
        self.seq.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for SessionHeader {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            connection_id: reader.decode()?,
            seq: reader.decode()?,
        })
    }
}
