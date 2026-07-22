use ::bytes::BufMut;
use ql_codec::Encode;
use ql_common::QID;

use crate::QL_WIRE_VERSION;

ql_codec::codec_struct! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RouteHeader {
        pub sender: QID,
        pub recipient: QID,
    }
}

impl RouteHeader {
    pub const WIRE_SIZE: usize = QID::SIZE * 2;
}

ql_codec::codec_struct! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SessionHeader {
        pub seq: RecordSeq,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RecordSeq(pub u64);

impl std::fmt::Display for RecordSeq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

ql_codec::varint_wrapper!(RecordSeq, u64);

impl SessionHeader {
    const AAD_DOMAIN: &[u8] = b"ql-wire:session-aad:v1";
    const AAD_RECORD_KIND_SESSION: u8 = 1;

    pub fn aad(&self, route: RouteHeader) -> Vec<u8> {
        let aad_len = Self::AAD_DOMAIN.len()
            + size_of::<u8>()
            + size_of::<u8>()
            + RouteHeader::WIRE_SIZE
            + self.seq.encoded_len();
        let mut aad = Vec::with_capacity(aad_len);
        aad.put_slice(Self::AAD_DOMAIN);
        aad.put_u8(QL_WIRE_VERSION);
        aad.put_u8(Self::AAD_RECORD_KIND_SESSION);
        route.encode(&mut aad);
        self.seq.encode(&mut aad);
        debug_assert_eq!(aad.len(), aad_len);
        aad
    }
}
