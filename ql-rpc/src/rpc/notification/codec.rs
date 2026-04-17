use bytes::BufMut;

use crate::{codec, notification::Notification};

pub fn encode_notification<M: Notification>(
    event: &M::Payload,
    out: &mut (impl BufMut + AsMut<[u8]>),
) {
    codec::encode_value_part(event, out)
}
