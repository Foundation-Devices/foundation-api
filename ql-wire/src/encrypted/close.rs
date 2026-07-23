ql_codec::codec! {
    /// closes the whole session immediately with a reset code.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SessionClose {
        pub code: SessionCloseCode,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SessionCloseCode(pub u64);

impl SessionCloseCode {
    pub const CANCELLED: Self = Self(0);
    pub const PROTOCOL: Self = Self(1);
    pub const TIMEOUT: Self = Self(2);
}

ql_codec::varint_wrapper!(SessionCloseCode, u64);
