use bytes::BufMut;

use crate::{notification::Notification, RpcCodec};

pub fn encode_notification<M: Notification>(
    payload: &M::Payload,
    out: &mut (impl BufMut + AsMut<[u8]>),
) {
    payload.encode_value(out)
}
