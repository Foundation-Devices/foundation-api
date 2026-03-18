use crate::{MethodId, RpcCodec};

pub trait Notification {
    const METHOD: MethodId;
    type Error;
    type Event: RpcCodec<Error = Self::Error>;
}

pub fn encode_event<M: Notification>(event: &M::Event, out: &mut Vec<u8>) -> Result<(), M::Error> {
    crate::header::RpcHeader::new(M::METHOD).encode_into(out);
    event.encode_value(out)
}

pub fn decode_event<M: Notification>(mut body: &[u8]) -> Result<M::Event, M::Error> {
    M::Event::decode_value(&mut body)
}

#[cfg(test)]
mod tests {
    use bytes::Buf;

    use super::{decode_event, encode_event, Notification};
    use crate::{parse_inbound, MethodId, RpcCodec};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct BytesValue(Vec<u8>);

    impl RpcCodec for BytesValue {
        type Error = core::convert::Infallible;

        fn encode_value(&self, out: &mut Vec<u8>) -> Result<(), Self::Error> {
            out.extend_from_slice(&self.0);
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
    fn event_round_trip_preserves_header_and_payload() {
        let mut encoded = Vec::new();
        encode_event::<Notify>(&BytesValue(b"hello".to_vec()), &mut encoded).unwrap();

        let inbound = parse_inbound(&encoded).unwrap();
        assert_eq!(inbound.header.method, Notify::METHOD);
        assert_eq!(
            decode_event::<Notify>(inbound.body).unwrap(),
            BytesValue(b"hello".to_vec())
        );
    }
}
