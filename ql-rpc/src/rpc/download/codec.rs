use std::marker::PhantomData;

use bytes::{BufMut, Bytes};

use crate::{codec, download::Download, ChunkQueue, CodecError, RpcCodec};

pub fn encode_request<M: Download>(request: &M::Request, out: &mut (impl BufMut + AsMut<[u8]>)) {
    request.encode_value(out)
}

pub fn encode_response_header<M: Download>(
    response_header: &M::ResponseHeader,
    out: &mut (impl BufMut + AsMut<[u8]>),
) {
    codec::encode_value_part(response_header, out)
}

pub enum ReadStep<M: Download> {
    NeedMore(ResponseHeaderReader<M>),
    ResponseHeader {
        value: M::ResponseHeader,
        bytes: ChunkQueue,
    },
}

pub struct ResponseHeaderReader<M: Download> {
    bytes: codec::ChunkQueue,
    marker: PhantomData<fn() -> M>,
}

impl<M: Download> Default for ResponseHeaderReader<M> {
    fn default() -> Self {
        Self {
            bytes: codec::ChunkQueue::default(),
            marker: PhantomData,
        }
    }
}

impl<M: Download> ResponseHeaderReader<M> {
    pub fn push(mut self, chunk: Bytes) -> Self {
        self.bytes.push(chunk);
        self
    }

    pub fn advance(mut self) -> Result<ReadStep<M>, CodecError<M::Error>> {
        let Some(mut body) = self.bytes.try_take_part()? else {
            return Ok(ReadStep::NeedMore(self));
        };

        let value = {
            let value = M::ResponseHeader::decode_value(&mut body).map_err(CodecError::Codec)?;
            drop(body);
            value
        };

        Ok(ReadStep::ResponseHeader {
            value,
            bytes: self.bytes,
        })
    }
}
