use crate::{MethodId, RpcCodec};

pub trait Request {
    const METHOD: MethodId;
    type Error;
    type Request: RpcCodec<Error = Self::Error>;
    type Response: RpcCodec<Error = Self::Error>;
}

pub fn encode_request<M: Request>(request: &M::Request, out: &mut Vec<u8>) -> Result<(), M::Error> {
    crate::header::RpcHeader::new(M::METHOD).encode_into(out);
    request.encode_value(out)
}

pub fn decode_request<M: Request>(body: &[u8]) -> Result<M::Request, M::Error> {
    let mut body = body;
    M::Request::decode_value(&mut body)
}

pub fn encode_response<M: Request>(
    response: &M::Response,
    out: &mut Vec<u8>,
) -> Result<(), M::Error> {
    response.encode_value(out)
}

pub fn decode_response<M: Request>(bytes: &[u8]) -> Result<M::Response, M::Error> {
    let mut bytes = bytes;
    M::Response::decode_value(&mut bytes)
}

#[cfg(test)]
mod tests {
    use bytes::Buf;

    use super::*;
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

    struct Echo;

    impl Request for Echo {
        const METHOD: MethodId = MethodId(7);
        type Error = core::convert::Infallible;
        type Request = BytesValue;
        type Response = BytesValue;
    }

    #[test]
    fn request_round_trip_preserves_header_and_payload() {
        let mut encoded = Vec::new();
        encode_request::<Echo>(&BytesValue(b"hello".to_vec()), &mut encoded).unwrap();

        let inbound = parse_inbound(&encoded).unwrap();
        assert_eq!(inbound.header.method, Echo::METHOD);
        assert_eq!(
            decode_request::<Echo>(inbound.body).unwrap(),
            BytesValue(b"hello".to_vec())
        );
    }

    #[test]
    fn response_round_trip_preserves_payload() {
        let mut encoded = Vec::new();
        encode_response::<Echo>(&BytesValue(b"done".to_vec()), &mut encoded).unwrap();
        assert_eq!(
            decode_response::<Echo>(&encoded).unwrap(),
            BytesValue(b"done".to_vec())
        );
    }
}
