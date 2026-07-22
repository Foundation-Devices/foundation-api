ql_codec::codec_newtype! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[repr(transparent)]
    pub struct HandshakeId(pub u32);
}
