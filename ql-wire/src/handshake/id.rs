ql_codec::codec_newtype! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[repr(transparent)]
    pub struct HandshakeId(pub u32);
}

impl HandshakeId {
    pub const WIRE_SIZE: usize = size_of::<u32>();
}
