use ql_codec::{ByteSlice, Decode, Encode};

use crate::{
    encrypted_message::EncryptedMessage,
    handshake::{Ik1, Ik2, Xx1, Xx2, Xx3, Xx4},
    Error, RouteHeader, SessionHeader, QL_WIRE_VERSION,
};

pub fn encode_record<W, T>(out: &mut W, header: RecordHeader, body: &T)
where
    W: bytes::BufMut + ?Sized,
    T: Encode + ?Sized,
{
    header.encode(out);
    body.encode(out);
}

pub fn encode_record_vec<T: Encode + ?Sized>(header: RecordHeader, body: &T) -> Vec<u8> {
    let mut out = Vec::with_capacity(RecordHeader::WIRE_SIZE + body.encoded_len());
    encode_record(&mut out, header, body);
    out
}

pub fn decode_record<T, B>(bytes: B) -> Result<(RecordHeader, T), Error>
where
    T: Decode<B>,
    B: ByteSlice,
{
    let mut reader = ql_codec::Reader::new(bytes);
    Ok((reader.decode()?, reader.decode()?))
}

ql_codec::codec_struct! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RecordHeader {
        pub version: u8,
        pub route: RouteHeader,
        pub record_type: RecordType,
    }
}

impl RecordHeader {
    pub const WIRE_SIZE: usize = size_of::<u8>() + RouteHeader::WIRE_SIZE + size_of::<u8>();

    pub fn new(route: RouteHeader, record_type: RecordType) -> Self {
        Self {
            version: QL_WIRE_VERSION,
            route,
            record_type,
        }
    }
}

ql_codec::codec_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RecordType {
        Handshake = 1,
        Session = 2,
    }
}

ql_codec::codec_enum! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum QlHandshakeRecord as HandshakeKind {
        Ik1(Ik1) = 1,
        Ik2(Ik2) = 2,
        Kk1(Ik1) = 3,
        Kk2(Ik2) = 4,
        Xx1(Xx1) = 5,
        Xx2(Xx2) = 6,
        Xx3(Xx3) = 7,
        Xx4(Xx4) = 8,
    }
}

ql_codec::codec_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct QlSessionRecord<B> {
        pub header: SessionHeader,
        pub payload: EncryptedMessage<B>,
    }
}

impl<B: ByteSlice> QlSessionRecord<B> {
    pub fn into_owned(self) -> QlSessionRecord<Vec<u8>> {
        QlSessionRecord {
            header: self.header,
            payload: self.payload.into_owned(),
        }
    }
}
