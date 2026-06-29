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

    pub const APP_STORE: ServiceId = ServiceId::from_u32(1);
    pub const BACKUP: ServiceId = ServiceId::from_u32(2);
    pub const BITCOIN: ServiceId = ServiceId::from_u32(3);
    pub const DEBUG: ServiceId = ServiceId::from_u32(4);
    pub const FIRMWARE: ServiceId = ServiceId::from_u32(5);
    pub const FX: ServiceId = ServiceId::from_u32(6);
    pub const SCV: ServiceId = ServiceId::from_u32(7);
    pub const TIME: ServiceId = ServiceId::from_u32(8);
}

/// Route key for a remote peer rpc
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceRouteKey {
    pub service_id: ServiceId,
    pub route_id: RouteId,
}

impl ql_rpc::RpcRouteKey for ServiceRouteKey {
    fn encoded_len(&self) -> usize {
        self.service_id.0.size() + self.route_id.0.size()
    }

    fn encode<W: bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.service_id.0.write_bytes(|bytes| out.put_slice(bytes));
        self.route_id.0.write_bytes(|bytes| out.put_slice(bytes));
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let (service_id, bytes) = ql_common::VarInt::decode_bytes(bytes)?;
        let (route_id, rest) = ql_common::VarInt::decode_bytes(bytes)?;
        rest.is_empty().then_some(Self {
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
        AppId::SIZE + self.route_id.0.size()
    }

    fn encode<W: bytes::BufMut + ?Sized>(&self, out: &mut W) {
        out.put_slice(&self.app_id.0);
        self.route_id.0.write_bytes(|bytes| out.put_slice(bytes));
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let app_id = AppId(bytes.get(..AppId::SIZE)?.try_into().ok()?);
        let (route_id, rest) = ql_common::VarInt::decode_bytes(&bytes[AppId::SIZE..])?;
        rest.is_empty().then_some(Self {
            app_id,
            route_id: RouteId(route_id),
        })
    }
}
