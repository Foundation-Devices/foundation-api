use bytes::BufMut;

use crate::{MethodId, RpcCodec};

pub trait Notification {
    const METHOD: MethodId;
    type Error;
    type Event: RpcCodec<Error = Self::Error>;
}

pub fn encode_event<M: Notification>(
    event: &M::Event,
    out: &mut impl BufMut,
) -> Result<(), M::Error> {
    event.encode_value(out)
}

pub fn decode_event<M: Notification>(mut body: &[u8]) -> Result<M::Event, M::Error> {
    M::Event::decode_value(&mut body)
}

#[cfg(test)]
mod tests {
    use bytes::{Buf, BufMut};

    use super::{decode_event, encode_event, Notification};
    use crate::{MethodId, RpcCodec};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct BytesValue(Vec<u8>);

    impl RpcCodec for BytesValue {
        type Error = core::convert::Infallible;

        fn encode_value<B: BufMut + ?Sized>(&self, out: &mut B) -> Result<(), Self::Error> {
            out.put_slice(&self.0);
            Ok(())
        }

        fn decode_value<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error> {
            Ok(Self(bytes.copy_to_bytes(bytes.remaining()).to_vec()))
        }
    }

    struct Notify;

    impl Notification for Notify {
        const METHOD: MethodId = MethodId(13);
        type Error = core::convert::Infallible;
        type Event = BytesValue;
    }

    #[test]
    fn event_round_trip_preserves_payload() {
        let mut encoded = Vec::new();
        encode_event::<Notify>(&BytesValue(b"hello".to_vec()), &mut encoded).unwrap();
        assert_eq!(
            decode_event::<Notify>(&encoded).unwrap(),
            BytesValue(b"hello".to_vec())
        );
    }
}
