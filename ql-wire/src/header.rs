use ::bytes::BufMut;

use crate::{codec, ByteSlice, WireEncode, WireError, QL_WIRE_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionHeader {
    pub connection_id: ConnectionId,
    pub seq: RecordSeq,
}

crate::varint_wrapper!(RecordSeq);

crate::array_wrapper!(ConnectionId, 16);

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
