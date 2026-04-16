use ql_wire::{CloseTarget, StreamClose, StreamCloseCode, StreamId};

use super::{
    state::{InboundState, StreamState},
    stream_rx::StreamReadIter,
    SessionEvent, EventSink, SessionFsm,
};
use crate::CommitReadError;

pub struct StreamOps<'a, E> {
    session: &'a mut SessionFsm,
    emit: E,
    stream_id: StreamId,
    stream_index: usize,
    reap_on_drop: bool,
}

impl<'a, E: EventSink> StreamOps<'a, E> {
    pub(super) fn new(
        session: &'a mut SessionFsm,
        stream_id: StreamId,
        stream_index: usize,
        emit: E,
    ) -> Self {
        Self {
            session,
            emit,
            stream_id,
            stream_index,
            reap_on_drop: false,
        }
    }

    /// returns this stream's identifier
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// returns the readable stream bytes as owned `Bytes` views without consuming them
    pub fn read(&self) -> StreamReadIter<'_> {
        self.stream().rx.bytes()
    }

    /// returns how many bytes can be read from the stream
    pub fn readable_bytes(&self) -> usize {
        self.stream().readable_bytes()
    }

    /// marks previously read bytes as consumed
    pub fn commit_read(&mut self, len: usize) -> Result<(), CommitReadError> {
        let stream_id = self.stream_id;
        let emit_finished = {
            let stream = self.stream_mut();
            if len > stream.readable_bytes() {
                return Err(CommitReadError);
            }
            stream.rx.consume(len);
            if stream.recv_limit() > stream.advertised_max_offset {
                stream.pending_window = true;
            }
            stream.route_id.is_some()
                && matches!(stream.inbound_state, InboundState::Finished)
                && stream.readable_bytes() == 0
        };
        if emit_finished {
            self.emit.emit(SessionEvent::Finished(stream_id));
        }
        self.reap_on_drop = true;
        Ok(())
    }

    /// returns a writer if the local write side is still open
    pub fn writer(&mut self) -> Option<StreamWriter<'_>> {
        let send_buffer_size = self.session.config.stream_send_buffer_size;
        let stream = self.stream_mut();
        if !stream.is_writable() {
            return None;
        }
        Some(StreamWriter::new(stream, send_buffer_size))
    }

    /// closes the origin lane, return lane, or both lanes of the stream
    pub fn close(&mut self, target: CloseTarget, code: StreamCloseCode) {
        let stream_id = self.stream_id;
        let stream = self.stream_mut();
        SessionFsm::apply_local_close_to_stream(stream, target);
        stream.pending_close = Some(StreamClose {
            stream_id,
            target,
            code,
        });
        self.reap_on_drop = true;
    }

    fn stream(&self) -> &StreamState {
        &self.session.state.streams[self.stream_index]
    }

    fn stream_mut(&mut self) -> &mut StreamState {
        &mut self.session.state.streams[self.stream_index]
    }
}

impl<E> Drop for StreamOps<'_, E> {
    fn drop(&mut self) {
        if !self.reap_on_drop {
            return;
        }

        self.session
            .try_reap_stream_at(self.stream_id, self.stream_index);
    }
}

pub struct StreamWriter<'a> {
    stream: &'a mut StreamState,
    send_buffer_size: usize,
}

impl<'a> StreamWriter<'a> {
    pub(super) fn new(stream: &'a mut StreamState, send_buffer_size: usize) -> Self {
        Self {
            stream,
            send_buffer_size,
        }
    }

    /// returns how many bytes can still be buffered for local writes
    pub fn capacity(&self) -> usize {
        self.stream.send_capacity(self.send_buffer_size)
    }

    /// appends as many bytes as possible and returns the accepted count
    pub fn write(&mut self, bytes: &mut bytes::Bytes) -> usize {
        let accepted = bytes.len().min(self.capacity());
        if accepted > 0 {
            self.stream.tx.append(bytes.split_to(accepted));
        }
        accepted
    }

    /// marks the local write side as finished
    pub fn finish(self) {
        self.stream.tx.queue_fin();
        self.stream.outbound_state = super::state::OutboundState::FinQueued;
    }
}
