use bytes::BufMut;

use crate::{codec, MethodId, ReadValueStep, RpcCodec, ValueReader};

pub trait Notification {
    const METHOD: MethodId;
    type Error;
    type Event: RpcCodec<Error = Self::Error>;
}

pub type EventReader<M> = ValueReader<<M as Notification>::Event>;
pub type EventReadStep<M> = ReadValueStep<<M as Notification>::Event>;

pub fn encode_event<M: Notification>(
    event: &M::Event,
    out: &mut (impl BufMut + AsMut<[u8]>),
) -> Result<(), M::Error> {
    codec::encode_value_part(event, out)
}
