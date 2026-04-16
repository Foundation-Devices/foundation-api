use bytes::BufMut;

use crate::{codec, notification::Notification};

pub fn encode_event<M: Notification>(event: &M::Event, out: &mut (impl BufMut + AsMut<[u8]>)) {
    codec::encode_value_part(event, out)
}
