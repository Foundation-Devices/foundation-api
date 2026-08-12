use ql_common::{ResetCode, StreamId};
use ql_wire::StreamReset;

use super::{
    state::{InboundState, OutboundState, StreamIoState, StreamState},
    SessionFsm,
};
use crate::{CommitReadError, ResetOrigin, StreamMeta, StreamResetEvent, StreamResetTarget};

pub struct StreamOps<'a, M: StreamMeta> {
    session: &'a mut SessionFsm<M>,
    stream_id: StreamId,
    stream_index: usize,
}

impl<'a, M: StreamMeta> StreamOps<'a, M> {
    pub(super) fn new(
        session: &'a mut SessionFsm<M>,
        stream_id: StreamId,
        stream_index: usize,
    ) -> Self {
        Self {
            session,
            stream_id,
            stream_index,
        }
    }

    pub fn metadata(&self) -> &M {
        &self.stream().metadata
    }

    pub fn metadata_mut(&mut self) -> &mut M {
        &mut self.stream_mut().metadata
    }

    pub fn io(&mut self) -> StreamIo<'_> {
        let stream_id = self.stream_id;
        let send_buffer_size = self.session.config.stream_send_buffer_size;
        StreamIo::new(stream_id, &mut self.stream_mut().io, send_buffer_size)
    }

    /// returns the metadata and stream I/O together
    pub fn split_mut(&mut self) -> (&mut M, StreamIo<'_>) {
        let stream_id = self.stream_id;
        let send_buffer_size = self.session.config.stream_send_buffer_size;
        let stream = self.stream_mut();
        (
            &mut stream.metadata,
            StreamIo::new(stream_id, &mut stream.io, send_buffer_size),
        )
    }

    #[inline]
    pub fn poll_readable(&mut self) {
        let (metadata, io) = self.split_mut();
        metadata.on_readable(io);
    }

    #[inline]
    pub fn poll_writable(&mut self) {
        let (metadata, io) = self.split_mut();
        metadata.on_writable(io);
    }

    /// resets the stream and notifies its metadata
    pub fn reset(&mut self, target: StreamResetTarget, code: ResetCode) {
        let stream_id = self.stream_id;
        let StreamState { metadata, io } = self.stream_mut();
        let wire_target = match target {
            StreamResetTarget::Reader => io.role.inbound_target(),
            StreamResetTarget::Writer => io.role.outbound_target(),
            StreamResetTarget::Both => ql_wire::ResetTarget::Both,
        };
        let reset = StreamReset {
            stream_id,
            target: wire_target,
            code,
        };
        if target.reader() {
            io.inbound_state = InboundState::Reset(reset.clone());
            io.reset_recv();
        }
        if target.writer() {
            io.outbound_state = OutboundState::Reset(reset.clone());
            io.tx.clear();
        }
        io.pending_reset = Some(reset);
        metadata.on_reset(StreamResetEvent {
            stream_id,
            code,
            target,
            origin: ResetOrigin::Local,
        });
    }

    #[inline]
    fn stream(&self) -> &StreamState<M> {
        &self.session.state.streams[self.stream_index]
    }

    #[inline]
    fn stream_mut(&mut self) -> &mut StreamState<M> {
        &mut self.session.state.streams[self.stream_index]
    }
}

impl<M: StreamMeta> Drop for StreamOps<'_, M> {
    fn drop(&mut self) {
        self.session.try_reap_stream(self.stream_id);
    }
}

/// I/O operations for one stream
pub struct StreamIo<'a> {
    stream_id: StreamId,
    state: &'a mut StreamIoState,
    send_buffer_size: usize,
}

impl<'a> StreamIo<'a> {
    pub(super) fn new(
        stream_id: StreamId,
        state: &'a mut StreamIoState,
        send_buffer_size: usize,
    ) -> Self {
        Self {
            stream_id,
            state,
            send_buffer_size,
        }
    }

    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub fn header(&self) -> &[u8] {
        self.state.header.as_ref().unwrap()
    }

    pub fn reader(&mut self) -> ReaderState<'_> {
        if let InboundState::Reset(reset) = &self.state.inbound_state {
            return ReaderState::Reset(reset.code);
        }
        let readable = self.state.readable_bytes() > 0;
        let finished = matches!(self.state.inbound_state, InboundState::Finished);
        match (readable, finished) {
            (true, true) => ReaderState::Final(StreamReader { state: self.state }),
            (true, false) => ReaderState::Readable(StreamReader { state: self.state }),
            (false, true) => ReaderState::Finished,
            (false, false) => ReaderState::Open,
        }
    }

    pub fn writer(&mut self) -> WriterState<'_> {
        if let OutboundState::Reset(reset) = &self.state.outbound_state {
            return WriterState::Reset(reset.code);
        }
        if matches!(
            self.state.outbound_state,
            OutboundState::FinQueued | OutboundState::Finished
        ) {
            return WriterState::Finished;
        }
        WriterState::Open(StreamWriter {
            state: self.state,
            send_buffer_size: self.send_buffer_size,
        })
    }
}

pub enum ReaderState<'a> {
    Open,
    Readable(StreamReader<'a>),
    Final(StreamReader<'a>),
    Finished,
    Reset(ResetCode),
}

impl<'a> ReaderState<'a> {
    pub fn active(self) -> Option<StreamReader<'a>> {
        match self {
            Self::Readable(reader) | Self::Final(reader) => Some(reader),
            Self::Open | Self::Finished | Self::Reset(_) => None,
        }
    }
}

pub enum WriterState<'a> {
    Open(StreamWriter<'a>),
    Finished,
    Reset(ResetCode),
}

impl<'a> WriterState<'a> {
    pub fn active(self) -> Option<StreamWriter<'a>> {
        match self {
            Self::Open(writer) => Some(writer),
            Self::Finished | Self::Reset(_) => None,
        }
    }
}

pub struct StreamReader<'a> {
    state: &'a mut StreamIoState,
}

impl StreamReader<'_> {
    /// returns the readable stream bytes as owned `Bytes` views without consuming them
    pub fn read(&self) -> impl Iterator<Item = bytes::Bytes> + '_ {
        self.state.rx.bytes()
    }

    /// returns how many bytes can be read from the stream
    pub fn readable_bytes(&self) -> usize {
        self.state.readable_bytes()
    }

    /// marks previously read bytes as consumed
    pub fn commit_read(&mut self, len: usize) -> Result<(), CommitReadError> {
        if len > self.state.readable_bytes() {
            return Err(CommitReadError);
        }
        self.state.rx.consume(len);
        if matches!(self.state.inbound_state, InboundState::Open)
            && self.state.recv_limit() > self.state.advertised_max_offset
        {
            self.state.pending_window = true;
        }
        Ok(())
    }
}

pub struct StreamWriter<'a> {
    state: &'a mut StreamIoState,
    send_buffer_size: usize,
}

impl StreamWriter<'_> {
    /// returns how many bytes can still be buffered for local writes
    pub fn capacity(&self) -> usize {
        self.state.send_capacity(self.send_buffer_size)
    }

    /// appends as many bytes as possible and returns the accepted count
    pub fn write(&mut self, bytes: &mut bytes::Bytes) -> usize {
        let accepted = bytes.len().min(self.capacity());
        if accepted > 0 {
            self.state.tx.append(bytes.split_to(accepted));
        }
        accepted
    }

    /// marks the local write side as finished
    pub fn finish(self) {
        self.state.tx.queue_fin();
        self.state.outbound_state = OutboundState::FinQueued;
    }
}
