use std::marker::PhantomData;

use bytes::{BufMut, Bytes};
use ql_common::ResetCode;

use crate::{codec, read_bytes, ChunkQueue, RpcCodec, RpcError, RpcRead};

/// reads a stream of framed byte parts
pub struct MultipartReader<H, R>
where
    H: RpcCodec,
    R: RpcRead,
{
    stream: R,
    frames: PartFrameReader<H>,
    /// prevents buffered frames from escaping after termination
    finished: bool,
}

/// reads the body of one multipart entry
pub struct MultipartPart<'a, H, R>
where
    H: RpcCodec,
    R: RpcRead,
{
    parent: &'a mut MultipartReader<H, R>,
    /// set after the part boundary so drop only resets abandoned parts
    finished: bool,
}

impl<H, R> MultipartReader<H, R>
where
    H: RpcCodec,
    R: RpcRead,
{
    pub fn new(stream: R, buffered: ChunkQueue) -> Self {
        Self {
            stream,
            frames: PartFrameReader::new(buffered),
            finished: false,
        }
    }

    pub async fn next_part(
        &mut self,
    ) -> Result<Option<(H, MultipartPart<'_, H, R>)>, RpcError<H::Error, R::Error>> {
        let Some(frame) = self.read_frame().await? else {
            return Ok(None);
        };

        let kind = match frame {
            PartFrame::PartHeader(value) => {
                return Ok(Some((
                    value,
                    MultipartPart {
                        parent: self,
                        finished: false,
                    },
                )));
            }
            PartFrame::BodyBytes(_) => FrameKind::BodyChunk,
            PartFrame::EndPart => FrameKind::EndPart,
        };

        self.reset_inner(ResetCode::PROTOCOL);
        Err(crate::Error::UnexpectedFrameKind(kind.tag()).into())
    }

    /// rejects any remaining part
    pub async fn complete(mut self) -> Result<(), RpcError<H::Error, R::Error>> {
        let Some(frame) = self.read_frame().await? else {
            return Ok(());
        };

        let kind = match frame {
            PartFrame::PartHeader(_) => FrameKind::PartHeader,
            PartFrame::BodyBytes(_) => FrameKind::BodyChunk,
            PartFrame::EndPart => FrameKind::EndPart,
        };

        self.reset_inner(ResetCode::PROTOCOL);
        Err(crate::Error::UnexpectedFrameKind(kind.tag()).into())
    }

    pub fn reset(mut self, code: ResetCode) {
        self.reset_inner(code);
    }

    async fn read_frame(&mut self) -> Result<Option<PartFrame<H>>, RpcError<H::Error, R::Error>> {
        if self.finished {
            return Ok(None);
        }

        loop {
            if let Some(frame) = self.frames.advance().inspect_err(|error| {
                self.reset_inner(error.reset_code().unwrap_or(ResetCode::DROPPED));
            })? {
                return Ok(Some(frame));
            }

            let chunk = read_bytes(&mut self.stream)
                .await
                .inspect_err(|_| self.finished = true)
                .map_err(RpcError::Transport)?;
            if chunk.is_empty() {
                self.finished = true;
                self.frames.finish()?;
                return Ok(None);
            }
            self.frames.push(chunk);
        }
    }

    fn reset_inner(&mut self, code: ResetCode) {
        self.finished = true;
        self.stream.reset(code);
    }
}

impl<H, R> MultipartPart<'_, H, R>
where
    H: RpcCodec,
    R: RpcRead,
{
    /// reads part bytes, returning an empty chunk at the end of the part
    pub async fn read_chunk(&mut self) -> Result<Bytes, RpcError<H::Error, R::Error>> {
        if self.finished {
            return Ok(Bytes::new());
        }

        let frame = self
            .parent
            .read_frame()
            .await
            .inspect_err(|_| self.finished = true)?;
        match frame {
            Some(PartFrame::BodyBytes(bytes)) => Ok(bytes),
            Some(PartFrame::EndPart) => {
                self.finished = true;
                Ok(Bytes::new())
            }
            Some(PartFrame::PartHeader(_)) => {
                self.parent.reset_inner(ResetCode::PROTOCOL);
                self.finished = true;
                Err(crate::Error::UnexpectedFrameKind(FrameKind::PartHeader.tag()).into())
            }
            None => {
                self.finished = true;
                Err(crate::Error::Truncated.into())
            }
        }
    }

    pub fn reset(mut self, code: ResetCode) {
        self.parent.reset_inner(code);
        self.finished = true;
    }
}

impl<H, R> Drop for MultipartPart<'_, H, R>
where
    H: RpcCodec,
    R: RpcRead,
{
    fn drop(&mut self) {
        if !self.finished {
            self.parent.reset_inner(ResetCode::DROPPED);
        }
    }
}

pub enum PartFrame<H: RpcCodec> {
    PartHeader(H),
    BodyBytes(Bytes),
    EndPart,
}

pub struct PartFrameReader<H: RpcCodec> {
    bytes: ChunkQueue,
    pending_frame: PendingFrame,
    marker: PhantomData<fn() -> H>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingFrame {
    None,
    Control { kind: FrameKind, len: usize },
    Body { remaining: usize },
}

impl<H: RpcCodec> PartFrameReader<H> {
    pub fn new(bytes: ChunkQueue) -> Self {
        Self {
            bytes,
            pending_frame: PendingFrame::None,
            marker: PhantomData,
        }
    }

    pub fn push(&mut self, chunk: Bytes) {
        self.bytes.push(chunk);
    }

    pub fn advance<E>(&mut self) -> Result<Option<PartFrame<H>>, RpcError<H::Error, E>> {
        loop {
            match std::mem::replace(&mut self.pending_frame, PendingFrame::None) {
                PendingFrame::Body { remaining } => {
                    if remaining == 0 {
                        continue;
                    }

                    let Some(bytes) = self.bytes.pop_front(remaining) else {
                        self.pending_frame = PendingFrame::Body { remaining };
                        return Ok(None);
                    };

                    let remaining = remaining - bytes.len();
                    self.pending_frame = if remaining == 0 {
                        PendingFrame::None
                    } else {
                        PendingFrame::Body { remaining }
                    };
                    return Ok(Some(PartFrame::BodyBytes(bytes)));
                }
                PendingFrame::Control { kind, len } => {
                    let Some(mut body) = self.bytes.try_take_body(len) else {
                        self.pending_frame = PendingFrame::Control { kind, len };
                        return Ok(None);
                    };

                    match kind {
                        FrameKind::PartHeader => {
                            let value = codec::decode_exact(&mut body)?;
                            return Ok(Some(PartFrame::PartHeader(value)));
                        }
                        FrameKind::BodyChunk => unreachable!("body chunk is not a control frame"),
                        FrameKind::EndPart => {
                            body.expect_empty().map_err(RpcError::Protocol)?;
                            return Ok(Some(PartFrame::EndPart));
                        }
                    }
                }
                PendingFrame::None => {
                    let Some((kind, len)) = self
                        .bytes
                        .try_take_tagged_part_header()
                        .map_err(RpcError::Protocol)?
                    else {
                        return Ok(None);
                    };

                    let kind = FrameKind::try_from(kind).map_err(RpcError::Protocol)?;
                    match kind {
                        FrameKind::BodyChunk => {
                            self.pending_frame = PendingFrame::Body { remaining: len };
                        }
                        FrameKind::EndPart if len != 0 => {
                            return Err(crate::Error::TrailingBytes.into());
                        }
                        FrameKind::PartHeader | FrameKind::EndPart => {
                            self.pending_frame = PendingFrame::Control { kind, len };
                        }
                    }
                }
            }
        }
    }

    pub fn finish(&self) -> Result<(), crate::Error> {
        if self.pending_frame == PendingFrame::None && self.bytes.remaining() == 0 {
            Ok(())
        } else {
            Err(crate::Error::Truncated)
        }
    }
}

pub fn encode_part_header<H: RpcCodec>(part_header: &H, out: &mut (impl BufMut + AsMut<[u8]>)) {
    codec::encode_tagged_value_part(FrameKind::PartHeader.tag(), part_header, out);
}

pub fn encode_body_chunk(bytes: &Bytes, out: &mut (impl BufMut + AsMut<[u8]>)) {
    codec::encode_tagged_value_part(FrameKind::BodyChunk.tag(), bytes, out);
}

pub fn encode_end_part(out: &mut (impl BufMut + AsMut<[u8]>)) {
    encode_tagged_empty_part(FrameKind::EndPart, out);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum FrameKind {
    PartHeader = 1,
    BodyChunk = 2,
    EndPart = 3,
}

impl FrameKind {
    pub fn tag(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for FrameKind {
    type Error = crate::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::PartHeader.tag() => Ok(Self::PartHeader),
            x if x == Self::BodyChunk.tag() => Ok(Self::BodyChunk),
            x if x == Self::EndPart.tag() => Ok(Self::EndPart),
            other => Err(crate::Error::UnexpectedFrameKind(other)),
        }
    }
}

fn encode_tagged_empty_part<B: BufMut + AsMut<[u8]>>(kind: FrameKind, out: &mut B) {
    out.put_u8(kind.tag());
    let payload_start = codec::reserve_length(out);
    codec::backpatch_length(out, payload_start);
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{
        encode_body_chunk, encode_end_part, encode_part_header, PartFrame, PartFrameReader,
    };

    #[test]
    fn part_reader_emits_multipart_sequence() {
        let mut encoded = Vec::new();
        encode_part_header(&b"a.txt".to_vec(), &mut encoded);
        encode_body_chunk(&Bytes::from_static(b"hel"), &mut encoded);
        encode_body_chunk(&Bytes::from_static(b"lo"), &mut encoded);
        encode_end_part(&mut encoded);
        encode_part_header(&b"b.txt".to_vec(), &mut encoded);
        encode_end_part(&mut encoded);

        let mut reader = PartFrameReader::<Vec<u8>>::new(Default::default());
        reader.push(Bytes::from(encoded));

        match reader.advance::<std::convert::Infallible>().unwrap() {
            Some(PartFrame::PartHeader(value)) => {
                assert_eq!(value, b"a.txt".to_vec());
            }
            _ => unreachable!(),
        }

        match reader.advance::<std::convert::Infallible>().unwrap() {
            Some(PartFrame::BodyBytes(bytes)) => assert_eq!(bytes, Bytes::from_static(b"hel")),
            _ => unreachable!(),
        }

        match reader.advance::<std::convert::Infallible>().unwrap() {
            Some(PartFrame::BodyBytes(bytes)) => assert_eq!(bytes, Bytes::from_static(b"lo")),
            _ => unreachable!(),
        }

        match reader.advance::<std::convert::Infallible>().unwrap() {
            Some(PartFrame::EndPart) => {}
            _ => unreachable!(),
        }

        match reader.advance::<std::convert::Infallible>().unwrap() {
            Some(PartFrame::PartHeader(value)) => {
                assert_eq!(value, b"b.txt".to_vec());
            }
            _ => unreachable!(),
        }

        match reader.advance::<std::convert::Infallible>().unwrap() {
            Some(PartFrame::EndPart) => {}
            _ => unreachable!(),
        }

        assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn part_reader_waits_for_complete_header_frame() {
        let mut encoded = Vec::new();
        encode_part_header(&b"a.txt".to_vec(), &mut encoded);
        let encoded = Bytes::from(encoded);

        let mut reader = PartFrameReader::<Vec<u8>>::new(Default::default());
        reader.push(encoded.slice(..4));
        assert!(reader
            .advance::<std::convert::Infallible>()
            .unwrap()
            .is_none());
        assert_eq!(reader.finish(), Err(crate::Error::Truncated));

        reader.push(encoded.slice(4..));
        match reader.advance::<std::convert::Infallible>().unwrap() {
            Some(PartFrame::PartHeader(value)) => assert_eq!(value, b"a.txt".to_vec()),
            _ => unreachable!(),
        }
        assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn body_chunk_frame_streams_after_header() {
        let mut encoded = Vec::new();
        encode_body_chunk(&Bytes::from_static(b"hello"), &mut encoded);
        let encoded = Bytes::from(encoded);

        let mut reader = PartFrameReader::<Vec<u8>>::new(Default::default());
        reader.push(encoded.slice(..9));
        assert!(reader
            .advance::<std::convert::Infallible>()
            .unwrap()
            .is_none());

        reader.push(encoded.slice(9..11));
        match reader.advance::<std::convert::Infallible>().unwrap() {
            Some(PartFrame::BodyBytes(bytes)) => assert_eq!(bytes, Bytes::from_static(b"he")),
            _ => unreachable!(),
        }

        reader.push(encoded.slice(11..));
        match reader.advance::<std::convert::Infallible>().unwrap() {
            Some(PartFrame::BodyBytes(bytes)) => assert_eq!(bytes, Bytes::from_static(b"llo")),
            _ => unreachable!(),
        }
    }

    #[test]
    fn part_reader_rejects_nonempty_end_part_from_header() {
        let mut encoded = Vec::new();
        encode_end_part(&mut encoded);
        encoded[1..9].copy_from_slice(&1u64.to_le_bytes());

        let mut reader = PartFrameReader::<Vec<u8>>::new(Default::default());
        reader.push(Bytes::from(encoded));

        assert!(matches!(
            reader.advance::<std::convert::Infallible>(),
            Err(crate::RpcError::Protocol(crate::Error::TrailingBytes))
        ));
    }
}
