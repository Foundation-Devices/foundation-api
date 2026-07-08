use ql_keyos::{AppId, RouteId, ServiceId};

pub mod app_id {
    use ql_keyos::AppId;

    pub const SYSTEM: AppId = AppId::from_hex("0x6f732f716c0000000000000000000000");
    pub const ONBOARDING: AppId = AppId::from_hex("0xdac5321775d449c11bc9c90f38067f8f");
    pub const BACKUP: AppId = AppId::from_hex("0xe19f16fcd9610bca7d026b4673f1cb06");
    pub const UPDATE: AppId = AppId::from_hex("0x6F732F75706461746500000000000000");
    pub const BITCOIN: AppId = AppId::from_hex("0x426974636f696e2057616c6c65740000");
    pub const DEBUG: AppId = AppId::from_hex("0x8ec0b4ea99704f9f973f5d7b7a3294b2");
}

pub mod service_id {
    use ql_keyos::ServiceId;

    pub const APP_STORE: ServiceId = ServiceId(1);
    pub const BACKUP: ServiceId = ServiceId(2);
    pub const BITCOIN: ServiceId = ServiceId(3);
    pub const DEBUG: ServiceId = ServiceId(4);
    pub const FIRMWARE: ServiceId = ServiceId(5);
    pub const FX: ServiceId = ServiceId(6);
    pub const SCV: ServiceId = ServiceId(7);
    pub const TIME: ServiceId = ServiceId(8);
}

/// Route key for a remote peer rpc
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceRouteKey {
    pub service_id: ServiceId,
    pub route_id: RouteId,
}

impl ql_rpc::RpcRouteKey for ServiceRouteKey {
    fn encoded_len(&self) -> usize {
        size_of::<u64>() + size_of::<u32>()
    }

    fn encode<W: bytes::BufMut + ?Sized>(&self, out: &mut W) {
        out.put_u64(self.service_id.0);
        out.put_u32(self.route_id.0);
    }

    fn decode(mut bytes: &[u8]) -> Option<Self> {
        let service_id = read_u64(&mut bytes)?;
        let route_id = read_u32(&mut bytes)?;
        bytes.is_empty().then_some(Self {
            service_id: ServiceId(service_id),
            route_id: RouteId(route_id),
        })
    }
}

impl ql_keyos::ServiceTargetKey for ServiceRouteKey {
    fn service_id(&self) -> ServiceId {
        self.service_id
    }
}

/// Route key for an keyos handled rpc
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AppRouteKey {
    pub app_id: AppId,
    pub route_id: RouteId,
}

impl ql_rpc::RpcRouteKey for AppRouteKey {
    fn encoded_len(&self) -> usize {
        AppId::SIZE + size_of::<u32>()
    }

    fn encode<W: bytes::BufMut + ?Sized>(&self, out: &mut W) {
        out.put_slice(&self.app_id.0);
        out.put_u32(self.route_id.0);
    }

    fn decode(mut bytes: &[u8]) -> Option<Self> {
        let app_id = AppId(bytes.get(..AppId::SIZE)?.try_into().ok()?);
        bytes = &bytes[AppId::SIZE..];
        let route_id = read_u32(&mut bytes)?;
        bytes.is_empty().then_some(Self {
            app_id,
            route_id: RouteId(route_id),
        })
    }
}

fn read_u64(bytes: &mut &[u8]) -> Option<u64> {
    let value = u64::from_be_bytes(bytes.get(..8)?.try_into().ok()?);
    *bytes = &bytes[8..];
    Some(value)
}

fn read_u32(bytes: &mut &[u8]) -> Option<u32> {
    let value = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?);
    *bytes = &bytes[4..];
    Some(value)
}
