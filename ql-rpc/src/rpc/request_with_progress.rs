use std::marker::PhantomData;

use bytes::{BufMut, Bytes};

use crate::{codec, CodecError, Error, RouteId, RpcCodec};

pub trait RequestWithProgress {
    const ROUTE: RouteId;
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
        Self {
            bytes: codec::ChunkQueue::new(),
            marker: PhantomData,
        }
    }
}

impl<M: RequestWithProgress> ResponseReader<M> {
    pub fn push(mut self, chunk: Bytes) -> Self {
        self.bytes.push(chunk);
        self
    }

    pub fn advance(self) -> Result<ReadStep<M>, CodecError<M::Error>> {
        let mut this = self;

        let Some((kind, mut body)) = this.bytes.try_take_tagged_part().map_err(CodecError::Rpc)?
        else {
            return Ok(ReadStep::NeedMore(this));
        };

        match kind {
            x if x == FrameKind::Progress as u8 => {
                let value = {
                    let value = M::Progress::decode_value(&mut body).map_err(CodecError::Codec)?;
                    drop(body);
                    value
                };
                Ok(ReadStep::Progress { value, next: this })
            }
            x if x == FrameKind::Response as u8 => {
                let response = M::Response::decode_value(&mut body).map_err(CodecError::Codec)?;
                drop(body);
                if this.bytes.remaining() > 0 {
                    Err(CodecError::Rpc(Error::TrailingBytes))
                } else {
                    Ok(ReadStep::Response(response))
                }
            }
            other => Err(CodecError::Rpc(Error::UnexpectedFrameKind(other))),
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
    out: &mut (impl BufMut + AsMut<[u8]>),
) {
    codec::encode_value_part(request, out)
}

pub fn encode_progress<M: RequestWithProgress>(
    progress: &M::Progress,
    out: &mut (impl BufMut + AsMut<[u8]>),
) {
    encode_tagged_value_part(FrameKind::Progress, progress, out)
}

pub fn encode_response<M: RequestWithProgress>(
    response: &M::Response,
    out: &mut (impl BufMut + AsMut<[u8]>),
) {
    encode_tagged_value_part(FrameKind::Response, response, out)
}

fn encode_tagged_value_part<T: RpcCodec, B: BufMut + AsMut<[u8]>>(
    kind: FrameKind,
    value: &T,
    out: &mut B,
) {
    out.put_u8(kind as u8);
    let payload_start = codec::reserve_length(out);
    value.encode_value(out);
    codec::backpatch_length(out, payload_start);
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{encode_progress, encode_response, ReadStep, RequestWithProgress, ResponseReader};
    use crate::RouteId;

    struct Watch;

    impl RequestWithProgress for Watch {
        const ROUTE: RouteId = RouteId::from_u32(11);
        type Error = core::convert::Infallible;
        type Request = Vec<u8>;
        type Progress = Vec<u8>;
        type Response = Vec<u8>;
    }

    #[test]
    fn response_reader_emits_progress_then_response() {
        let mut encoded = Vec::new();
        encode_progress::<Watch>(&b"10%".to_vec(), &mut encoded);
        encode_response::<Watch>(&b"done".to_vec(), &mut encoded);

        let reader = match ResponseReader::<Watch>::default()
            .push(Bytes::from(encoded))
            .advance()
            .unwrap()
        {
            ReadStep::Progress { value, next } => {
                assert_eq!(value, b"10%".to_vec());
                next
            }
            _ => unreachable!(),
        };
        match reader.advance().unwrap() {
            ReadStep::Response(value) => assert_eq!(value, b"done".to_vec()),
            _ => unreachable!(),
        }
    }

    #[test]
    fn response_reader_handles_response_only() {
        let mut encoded = Vec::new();
        encode_response::<Watch>(&b"done".to_vec(), &mut encoded);

        match ResponseReader::<Watch>::default()
            .push(Bytes::from(encoded))
            .advance()
            .unwrap()
        {
            ReadStep::Response(value) => assert_eq!(value, b"done".to_vec()),
            _ => unreachable!(),
        }
    }
}
