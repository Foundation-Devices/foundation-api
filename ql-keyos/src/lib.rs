//! KeyOS addressing primitives for QuantumLink

use ql_codec::{ByteSlice, Decode, Encode, Reader};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct AppId(pub [u8; Self::SIZE]);

impl AppId {
    pub const SIZE: usize = 16;

    pub const fn from_hex(hex: &str) -> Self {
        const fn nibble(byte: u8) -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hex digit"),
            }
        }
        let bytes = hex.as_bytes();
        if bytes.len() != Self::SIZE * 2 + 2 || bytes[0] != b'0' || bytes[1] != b'x' {
            panic!("app id must be 0x followed by 32 hex digits")
        }

        let mut app_id = [0; Self::SIZE];
        let mut i = 0;
        while i < Self::SIZE {
            app_id[i] = (nibble(bytes[i * 2 + 2]) << 4) | nibble(bytes[i * 2 + 3]);
            i += 1;
        }

        Self(app_id)
    }
}

impl Encode for AppId {
    fn encoded_len(&self) -> usize {
        Self::SIZE
    }

    fn encode<W: bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.0.encode(out);
    }
}

impl<B: ByteSlice> Decode<B> for AppId {
    fn decode(reader: &mut Reader<B>) -> Result<Self, ql_codec::Error> {
        Ok(Self(reader.decode()?))
    }
}

// todo: version
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeerPermissions {
    /// KeyOS app ids this peer is allowed to open streams toward
    pub app_ids: Vec<AppId>,
    /// Service ids this peer advertises for KeyOS-opened streams
    pub service_ids: Vec<ServiceId>,
}

macro_rules! wrapper {
    ($(#[$attr:meta])* $name:ident, $ty:ty) => {
        $(#[$attr])*
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[repr(transparent)]
        pub struct $name(pub $ty);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

wrapper!(
    /// Identifier for a route within a KeyOS app or service namespace
    RouteId,
    u32
);
wrapper!(
    /// Identifier for a KeyOS service advertised by a peer
    ServiceId,
    u64
);

ql_codec::varint_wrapper!(RouteId, u32);
ql_codec::varint_wrapper!(ServiceId, u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceRouteKey {
    pub service_id: ServiceId,
    pub route_id: RouteId,
}

impl ql_rpc::RpcRouteKey for ServiceRouteKey {
    fn encoded_len(&self) -> usize {
        self.service_id.encoded_len() + self.route_id.encoded_len()
    }

    fn encode<W: bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.service_id.encode(out);
        self.route_id.encode(out);
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);
        let key = Self {
            service_id: reader.decode().ok()?,
            route_id: reader.decode().ok()?,
        };
        reader.is_empty().then_some(key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AppRouteKey {
    pub app_id: AppId,
    pub route_id: RouteId,
}

impl ql_rpc::RpcRouteKey for AppRouteKey {
    fn encoded_len(&self) -> usize {
        self.app_id.encoded_len() + self.route_id.encoded_len()
    }

    fn encode<W: bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.app_id.encode(out);
        self.route_id.encode(out);
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);
        let key = Self {
            app_id: reader.decode().ok()?,
            route_id: reader.decode().ok()?,
        };
        reader.is_empty().then_some(key)
    }
}
