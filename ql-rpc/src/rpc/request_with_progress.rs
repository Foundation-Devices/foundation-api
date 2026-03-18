use std::{collections::VecDeque, marker::PhantomData};

use bytes::Buf;

use crate::{codec, MethodId, RpcCodec, RpcCodecError, RpcError};

const FRAME_HEADER_SIZE: usize = 1 + core::mem::size_of::<u64>();

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
    bytes: VecDeque<u8>,
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
            bytes: VecDeque::new(),
            marker: PhantomData,
        }
    }

    pub fn push(mut self, chunk: &[u8]) -> Self {
        self.bytes.extend(chunk);
        self
    }

    pub fn advance(self) -> Result<ReadStep<M>, RpcCodecError<M::Error>> {
        let mut this = self;

        let (first, second) = this.bytes.as_slices();
        let Some((kind, consumed, payload_len)) =
            codec::try_measure_next_tagged_part(first.chain(second)).map_err(RpcCodecError::Rpc)?
        else {
            return Ok(ReadStep::NeedMore(this));
        };

        match kind {
            x if x == FrameKind::Progress as u8 => {
                this.bytes.drain(..FRAME_HEADER_SIZE);
                let value = {
                    let mut body = codec::DrainBuf::new(&mut this.bytes, payload_len);
                    M::Progress::decode_value(&mut body).map_err(RpcCodecError::Codec)?
                };
                Ok(ReadStep::Progress { value, next: this })
            }
            x if x == FrameKind::Response as u8 => {
                let has_trailing = this.bytes.len() > consumed;
                this.bytes.drain(..FRAME_HEADER_SIZE);
                let mut body = codec::DrainBuf::new(&mut this.bytes, payload_len);
                let response =
                    M::Response::decode_value(&mut body).map_err(RpcCodecError::Codec)?;
                if has_trailing {
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
    out: &mut Vec<u8>,
) -> Result<(), M::Error> {
    crate::header::RpcHeader::new(M::METHOD).encode_into(out);
    request.encode_value(out)
}

pub fn decode_request<M: RequestWithProgress>(mut body: &[u8]) -> Result<M::Request, M::Error> {
    M::Request::decode_value(&mut body)
}

pub fn encode_progress<M: RequestWithProgress>(
    progress: &M::Progress,
    out: &mut Vec<u8>,
) -> Result<(), M::Error> {
    encode_tagged_value_part(FrameKind::Progress, progress, out)
}

pub fn encode_response<M: RequestWithProgress>(
    response: &M::Response,
    out: &mut Vec<u8>,
) -> Result<(), M::Error> {
    encode_tagged_value_part(FrameKind::Response, response, out)
}

fn encode_tagged_value_part<T: RpcCodec>(
    kind: FrameKind,
    value: &T,
    out: &mut Vec<u8>,
) -> Result<(), T::Error> {
    let mut payload = Vec::new();
    value.encode_value(&mut payload)?;
    out.push(kind as u8);
    codec::push_length(out, payload.len());
    out.extend_from_slice(&payload);
    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::Buf;

    use super::{
        decode_request, encode_progress, encode_request, encode_response, ReadStep,
        RequestWithProgress, ResponseReader,
    };
    use crate::{parse_inbound, MethodId, RpcCodec, RpcCodecError, RpcError};

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

        let inbound = parse_inbound(&encoded).unwrap();
        assert_eq!(inbound.header.method, Watch::METHOD);
        assert_eq!(
            decode_request::<Watch>(inbound.body).unwrap(),
            BytesValue(b"watch".to_vec())
        );
    }

    #[test]
    fn response_with_progress_requires_terminal_response() {
        let mut encoded = Vec::new();
        encode_progress::<Watch>(&BytesValue(b"10%".to_vec()), &mut encoded).unwrap();

        let reader = match ResponseReader::<Watch>::new()
            .push(&encoded)
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
            .push(&encoded)
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

        let reader = ResponseReader::<Watch>::new().push(&encoded[..4]);
        let reader = match reader.advance().unwrap() {
            ReadStep::NeedMore(next) => next,
            _ => unreachable!(),
        };
        let reader = reader.push(&encoded[4..encoded.len() - 2]);
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
        let reader = reader.push(&encoded[encoded.len() - 2..]);
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
            .push(&encoded)
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
            .push(&encoded)
            .advance()
            .unwrap()
        {
            ReadStep::Response(value) => assert_eq!(value, BytesValue(b"done".to_vec())),
            _ => unreachable!(),
        }
    }
}
