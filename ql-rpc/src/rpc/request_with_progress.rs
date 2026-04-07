use std::marker::PhantomData;

use bytes::{BufMut, Bytes};

use crate::{codec, MethodId, RpcCodec, RpcCodecError, RpcError};

pub trait RequestWithProgress {
    const METHOD: MethodId;
    type Error;
    type Request: RpcCodec<Error = Self::Error>;
    type Progress: RpcCodec<Error = Self::Error>;
    type Response: RpcCodec<Error = Self::Error>;
}

pub enum ReadStep<M: RequestWithProgress> {
    NeedMore(ResponseReader<M>),
    Progress {
        value: M::Progress,
        next: ResponseReader<M>,
    },
    Response(M::Response),
}

pub struct ResponseReader<M: RequestWithProgress> {
    bytes: codec::ChunkQueue,
    marker: PhantomData<fn() -> M>,
}

impl<M: RequestWithProgress> Default for ResponseReader<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: RequestWithProgress> ResponseReader<M> {
    pub fn new() -> Self {
        Self {
            bytes: codec::ChunkQueue::new(),
            marker: PhantomData,
        }
    }

    pub fn push(mut self, chunk: Bytes) -> Self {
        self.bytes.push(chunk);
        self
    }

    pub fn advance(self) -> Result<ReadStep<M>, RpcCodecError<M::Error>> {
        let mut this = self;

        let Some((kind, mut body)) =
            this.bytes.try_take_tagged_part().map_err(RpcCodecError::Rpc)?
        else {
            return Ok(ReadStep::NeedMore(this));
        };

        match kind {
            x if x == FrameKind::Progress as u8 => {
                let value = {
                    let value =
                        M::Progress::decode_value(&mut body).map_err(RpcCodecError::Codec)?;
                    drop(body);
                    value
                };
                Ok(ReadStep::Progress { value, next: this })
            }
            x if x == FrameKind::Response as u8 => {
                let response =
                    M::Response::decode_value(&mut body).map_err(RpcCodecError::Codec)?;
                drop(body);
                if this.bytes.remaining() > 0 {
                    Err(RpcCodecError::Rpc(RpcError::TrailingBytes))
                } else {
                    Ok(ReadStep::Response(response))
                }
            }
            other => Err(RpcCodecError::Rpc(RpcError::UnexpectedFrameKind(other))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum FrameKind {
    Progress = 1,
    Response = 2,
}

pub fn encode_request<M: RequestWithProgress>(
    request: &M::Request,
    out: &mut impl BufMut,
) -> Result<(), M::Error> {
    crate::header::RpcHeader::new(M::METHOD)
        .encode_value(out)
        .expect("rpc header encoding cannot fail");
    request.encode_value(out)
}

pub fn decode_request<M: RequestWithProgress>(mut body: &[u8]) -> Result<M::Request, M::Error> {
    M::Request::decode_value(&mut body)
}

pub fn encode_progress<M: RequestWithProgress>(
    progress: &M::Progress,
    out: &mut (impl BufMut + AsMut<[u8]>),
) -> Result<(), M::Error> {
    encode_tagged_value_part(FrameKind::Progress, progress, out)
}

pub fn encode_response<M: RequestWithProgress>(
    response: &M::Response,
    out: &mut (impl BufMut + AsMut<[u8]>),
) -> Result<(), M::Error> {
    encode_tagged_value_part(FrameKind::Response, response, out)
}

fn encode_tagged_value_part<T: RpcCodec, B: BufMut + AsMut<[u8]>>(
    kind: FrameKind,
    value: &T,
    out: &mut B,
) -> Result<(), T::Error> {
    out.put_u8(kind as u8);
    let payload_start = codec::reserve_length(out);
    value.encode_value(out)?;
    codec::backpatch_length(out, payload_start);
    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::{Buf, BufMut, Bytes};

    use super::{
        decode_request, encode_progress, encode_request, encode_response, ReadStep,
        RequestWithProgress, ResponseReader,
    };
    use crate::{header::RpcHeader, MethodId, RpcCodec, RpcCodecError, RpcError};

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

    struct Watch;

    impl RequestWithProgress for Watch {
        const METHOD: MethodId = MethodId(11);
        type Error = core::convert::Infallible;
        type Request = BytesValue;
        type Progress = BytesValue;
        type Response = BytesValue;
    }

    #[test]
    fn request_round_trip_preserves_header_and_payload() {
        let mut encoded = Vec::new();
        encode_request::<Watch>(&BytesValue(b"watch".to_vec()), &mut encoded).unwrap();

        let mut body = encoded.as_slice();
        let header = RpcHeader::decode_value(&mut body).unwrap();
        assert_eq!(header.method, Watch::METHOD);
        assert_eq!(
            decode_request::<Watch>(body).unwrap(),
            BytesValue(b"watch".to_vec())
        );
    }

    #[test]
    fn response_with_progress_requires_terminal_response() {
        let mut encoded = Vec::new();
        encode_progress::<Watch>(&BytesValue(b"10%".to_vec()), &mut encoded).unwrap();

        let reader = match ResponseReader::<Watch>::new()
            .push(Bytes::from(encoded))
            .advance()
            .unwrap()
        {
            ReadStep::Progress { value, next } => {
                assert_eq!(value, BytesValue(b"10%".to_vec()));
                next
            }
            _ => unreachable!(),
        };
        let reader = match reader.advance().unwrap() {
            ReadStep::NeedMore(next) => next,
            _ => unreachable!(),
        };
        let _ = reader;
    }

    #[test]
    fn response_with_progress_rejects_bytes_after_response() {
        let mut encoded = Vec::new();
        encode_progress::<Watch>(&BytesValue(b"10%".to_vec()), &mut encoded).unwrap();
        encode_response::<Watch>(&BytesValue(b"done".to_vec()), &mut encoded).unwrap();
        encode_progress::<Watch>(&BytesValue(b"late".to_vec()), &mut encoded).unwrap();

        let reader = match ResponseReader::<Watch>::new()
            .push(Bytes::from(encoded))
            .advance()
            .unwrap()
        {
            ReadStep::Progress { next, .. } => next,
            _ => unreachable!(),
        };
        match reader.advance() {
            Err(RpcCodecError::Rpc(RpcError::TrailingBytes)) => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn response_reader_emits_typed_events() {
        let mut encoded = Vec::new();
        encode_progress::<Watch>(&BytesValue(b"10%".to_vec()), &mut encoded).unwrap();
        encode_response::<Watch>(&BytesValue(b"done".to_vec()), &mut encoded).unwrap();

        let encoded = Bytes::from(encoded);
        let reader = ResponseReader::<Watch>::new().push(encoded.slice(..4));
        let reader = match reader.advance().unwrap() {
            ReadStep::NeedMore(next) => next,
            _ => unreachable!(),
        };
        let reader = reader.push(encoded.slice(4..encoded.len() - 2));
        let reader = match reader.advance().unwrap() {
            ReadStep::Progress {
                value: BytesValue(bytes),
                next,
            } => {
                assert_eq!(bytes, b"10%".to_vec());
                next
            }
            _ => unreachable!(),
        };
        let reader = match reader.advance().unwrap() {
            ReadStep::NeedMore(next) => next,
            _ => unreachable!(),
        };
        let reader = reader.push(encoded.slice(encoded.len() - 2..));
        match reader.advance().unwrap() {
            ReadStep::Response(value) => assert_eq!(value, BytesValue(b"done".to_vec())),
            _ => unreachable!(),
        }
    }

    #[test]
    fn response_progress_then_response_round_trips() {
        let mut encoded = Vec::new();
        encode_progress::<Watch>(&BytesValue(b"10%".to_vec()), &mut encoded).unwrap();
        encode_response::<Watch>(&BytesValue(b"done".to_vec()), &mut encoded).unwrap();

        let reader = match ResponseReader::<Watch>::new()
            .push(Bytes::from(encoded))
            .advance()
            .unwrap()
        {
            ReadStep::Progress { value, next } => {
                assert_eq!(value, BytesValue(b"10%".to_vec()));
                next
            }
            _ => unreachable!(),
        };
        match reader.advance().unwrap() {
            ReadStep::Response(value) => assert_eq!(value, BytesValue(b"done".to_vec())),
            _ => unreachable!(),
        }
    }

    #[test]
    fn response_can_be_encoded_without_progress() {
        let mut encoded = Vec::new();
        encode_response::<Watch>(&BytesValue(b"done".to_vec()), &mut encoded).unwrap();

        match ResponseReader::<Watch>::new()
            .push(Bytes::from(encoded))
            .advance()
            .unwrap()
        {
            ReadStep::Response(value) => assert_eq!(value, BytesValue(b"done".to_vec())),
            _ => unreachable!(),
        }
    }
}
