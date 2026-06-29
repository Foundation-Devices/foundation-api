//! KeyOS addressing primitives for QuantumLink

use bytes::BufMut;
pub use ql_common::VarInt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct AppId(pub [u8; Self::SIZE]);

impl AppId {
    pub const SIZE: usize = 16;

    pub const fn from_hex(hex: &str) -> Self {
        const fn hex_nibble(byte: u8) -> u8 {
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
            app_id[i] = (hex_nibble(bytes[i * 2 + 2]) << 4) | hex_nibble(bytes[i * 2 + 3]);
            i += 1;
        }

        Self(app_id)
    }
}

ql_common::varint_wrapper!(
    /// Identifier for a route within a KeyOS app or service namespace
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(into = "u64", try_from = "u64"))]
    RouteId
);

ql_common::varint_wrapper!(
    /// Identifier for a KeyOS service advertised by a peer
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(into = "u64", try_from = "u64"))]
    ServiceId
);

pub trait ServiceTargetKey {
    fn service_id(&self) -> ServiceId;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeerMetadata {
    /// KeyOS app ids this peer is allowed to open streams toward
    pub app_ids: Vec<AppId>,
    /// Service ids this peer advertises for KeyOS-opened streams
    pub service_ids: Vec<ServiceId>,
}

impl PeerMetadata {
    pub fn write_bytes<B: BufMut + ?Sized>(&self, out: &mut B) {
        write_varint(len_varint(self.app_ids.len()), out);
        for app_id in &self.app_ids {
            out.put_slice(&app_id.0);
        }

        write_varint(len_varint(self.service_ids.len()), out);
        for service_id in &self.service_ids {
            write_varint(service_id.0, out);
        }
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Option<Self> {
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
            let (service_id, rest) = VarInt::decode_bytes(bytes)?;
            bytes = rest;
            service_ids.push(ServiceId(service_id));
        }

        bytes.is_empty().then_some(Self {
            app_ids,
            service_ids,
        })
    }
}

fn len_varint(len: usize) -> VarInt {
    VarInt::from_u64(len as u64).expect("metadata length exceeds varint bounds")
}

fn read_len(bytes: &mut &[u8]) -> Option<usize> {
    let (len, rest) = VarInt::decode_bytes(bytes)?;
    *bytes = rest;
    usize::try_from(len.into_inner()).ok()
}

fn write_varint<B: BufMut + ?Sized>(value: VarInt, out: &mut B) {
    value.write_bytes(|bytes| out.put_slice(bytes));
}
