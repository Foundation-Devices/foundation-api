use bytes::Bytes;

use super::state::{OutboundState, StreamState};

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

    pub fn capacity(&self) -> usize {
        self.stream.send_capacity(self.send_buffer_size)
    }

    pub fn write(&mut self, bytes: &mut Bytes) -> usize {
        let accepted = bytes.len().min(self.capacity());
        if accepted > 0 {
            self.stream.tx.append(bytes.split_to(accepted));
        }
        accepted
    }

    pub fn finish(self) {
        self.stream.tx.queue_fin();
        self.stream.outbound_state = OutboundState::FinQueued;
    }
}
