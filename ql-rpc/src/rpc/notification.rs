use bytes::BufMut;

use crate::{codec, RouteId, RpcCodec};

pub trait Notification {
    const METHOD: RouteId;
    type Error;
    type Event: RpcCodec<Error = Self::Error>;
}

pub fn encode_event<M: Notification>(event: &M::Event, out: &mut (impl BufMut + AsMut<[u8]>)) {
    codec::encode_value_part(event, out)
}
