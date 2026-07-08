//! KeyOS addressing primitives for QuantumLink

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

// TODO: version
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeerMetadata {
    /// KeyOS app ids this peer is allowed to open streams toward
    pub app_ids: Vec<AppId>,
    /// Service ids this peer advertises for KeyOS-opened streams
    pub service_ids: Vec<ServiceId>,
}

impl PeerMetadata {
    pub fn write_bytes(&self, out: &mut Vec<u8>) {
        fn len_u64(len: usize) -> u64 {
            len.try_into().expect("metadata length exceeds u64")
        }

        out.extend_from_slice(&len_u64(self.app_ids.len()).to_be_bytes());
        for app_id in &self.app_ids {
            out.extend_from_slice(&app_id.0);
        }

        out.extend_from_slice(&len_u64(self.service_ids.len()).to_be_bytes());
        for service_id in &self.service_ids {
            out.extend_from_slice(&service_id.0.to_be_bytes());
        }
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Option<Self> {
        fn read_len(bytes: &mut &[u8]) -> Option<usize> {
            read_u64(bytes)?.try_into().ok()
        }
        fn read_u64(bytes: &mut &[u8]) -> Option<u64> {
            let value = u64::from_be_bytes(bytes.get(..8)?.try_into().ok()?);
            *bytes = &bytes[8..];
            Some(value)
        }

        let app_count = read_len(&mut bytes)?;
        let app_bytes_len = app_count.checked_mul(AppId::SIZE)?;
        if app_bytes_len > bytes.len() {
            return None;
        }
        let mut app_ids = Vec::with_capacity(app_count);
        for _ in 0..app_count {
            let app_id = AppId(bytes.get(..AppId::SIZE)?.try_into().ok()?);
            bytes = &bytes[AppId::SIZE..];
            app_ids.push(app_id);
        }

        let service_count = read_len(&mut bytes)?;
        if service_count > bytes.len() {
            return None;
        }
        let mut service_ids = Vec::with_capacity(service_count);
        for _ in 0..service_count {
            service_ids.push(ServiceId(read_u64(&mut bytes)?));
        }

        bytes.is_empty().then_some(Self {
            app_ids,
            service_ids,
        })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::default();
        self.write_bytes(&mut bytes);
        bytes
    }
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

pub trait ServiceTargetKey {
    fn service_id(&self) -> ServiceId;
}
