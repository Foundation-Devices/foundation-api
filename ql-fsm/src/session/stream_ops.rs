use ql_common::{ResetCode, StreamId};
use ql_wire::StreamReset;

use super::{
    state::{InboundState, StreamState},
    stream_rx::StreamReadIter,
    EventSink, SessionEvent, SessionFsm,
};
use crate::{CommitReadError, StreamResetTarget};

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
    #[inline]
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// returns the streams details
    #[inline]
    pub fn header(&self) -> &[u8] {
        self.stream().header.as_ref().unwrap()
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
            stream.header.is_some()
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

    /// resets the local read side, write side, or both sides of the stream
    pub fn reset(&mut self, target: StreamResetTarget, code: ResetCode) {
        let stream_id = self.stream_id;
        let stream = self.stream_mut();
        let wire_target = match target {
            StreamResetTarget::Reader => stream.role.inbound_target(),
            StreamResetTarget::Writer => stream.role.outbound_target(),
            StreamResetTarget::Both => ql_wire::ResetTarget::Both,
        };
        SessionFsm::apply_local_reset_to_stream(stream, wire_target);
        stream.pending_reset = Some(StreamReset {
            stream_id,
            target: wire_target,
            code,
        });
        self.reap_on_drop = true;
    }

    #[inline]
    fn stream(&self) -> &StreamState {
        &self.session.state.streams[self.stream_index]
    }

    #[inline]
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
