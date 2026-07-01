use ql_common::{RouteId, ServiceId, VarInt};

use crate::RouteKey;

pub fn encode_stream_header<R: crate::Route>() -> Box<[u8]> {
    encode_route_key(RouteKey::new::<R>())
}

pub fn encode_route_key(key: RouteKey) -> Box<[u8]> {
    let mut out = Vec::with_capacity(ServiceId::SIZE + key.route_id.0.size());
    out.extend_from_slice(&key.service_id.0);
    key.route_id
        .0
        .write_bytes(|bytes| out.extend_from_slice(bytes));
    out.into_boxed_slice()
}

pub fn decode_stream_header(bytes: &[u8]) -> Option<RouteKey> {
    let service_id = ServiceId(bytes.get(..ServiceId::SIZE)?.try_into().ok()?);
    let (route_id, rest) = VarInt::decode_bytes(&bytes[ServiceId::SIZE..])?;
    rest.is_empty().then_some(RouteKey {
        service_id,
        route_id: RouteId(route_id),
    })
}
