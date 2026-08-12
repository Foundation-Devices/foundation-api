use bytes::Bytes;
use ql_fsm::{OutboundWrite, ReaderState, StreamIo, StreamMeta, StreamResetEvent, WriterState};

use crate::{
    command::Command,
    io::{Rx, Tx},
    log, QlStreamError,
};

pub struct DriverState {
    pub runtime_tx: async_channel::Sender<Command>,
    pub max_concurrent_message_writes: usize,
    pub terminal_write: Option<OutboundWrite>,
}

#[derive(Default)]
pub struct DriverStreamIo {
    outbound: Option<OutboundIo>,
    inbound: Option<Rx>,
}

struct OutboundIo {
    tx: Tx,
    pending: Bytes,
}

impl DriverStreamIo {
    pub fn initialize(&mut self, tx: Tx, rx: Rx, mut stream: StreamIo<'_>) {
        self.outbound = match stream.writer() {
            WriterState::Open(_) => Some(OutboundIo {
                tx,
                pending: Bytes::new(),
            }),
            WriterState::Finished => {
                tx.finish();
                None
            }
            WriterState::Reset(code) => {
                let error = QlStreamError::StreamReset {
                    code,
                    origin: crate::ResetOrigin::Peer,
                };
                let _ = tx.fail(error);
                None
            }
        };
        self.inbound = match stream.reader() {
            ReaderState::Open | ReaderState::Readable(_) | ReaderState::Final(_) => Some(rx),
            ReaderState::Finished => {
                rx.finish();
                None
            }
            ReaderState::Reset(code) => {
                let error = QlStreamError::StreamReset {
                    code,
                    origin: crate::ResetOrigin::Peer,
                };
                rx.fail(error);
                None
            }
        };
        self.poll_inbound(stream);
    }

    fn outbound_fail(&mut self, error: QlStreamError) {
        if let Some(outbound) = self.outbound.take() {
            let _ = outbound.tx.fail(error);
        }
    }

    fn inbound_fail(&mut self, error: QlStreamError) {
        if let Some(inbound) = self.inbound.take() {
            inbound.fail(error);
        }
    }

    pub fn poll_inbound(&mut self, mut stream: StreamIo<'_>) {
        let stream_id = stream.stream_id();
        let (mut reader, finished) = match stream.reader() {
            ReaderState::Open => return,
            ReaderState::Readable(reader) => (reader, false),
            ReaderState::Final(reader) => (reader, true),
            ReaderState::Finished => {
                if let Some(inbound) = self.inbound.take() {
                    inbound.finish();
                }
                return;
            }
            ReaderState::Reset(code) => {
                self.inbound_fail(QlStreamError::StreamReset {
                    code,
                    origin: crate::ResetOrigin::Peer,
                });
                return;
            }
        };
        let Some(inbound) = self.inbound.as_ref() else {
            return;
        };

        log::trace!(
            "draining inbound bytes: stream_id={stream_id} readable={}",
            reader.readable_bytes()
        );
        let mut accepted = 0usize;
        for chunk in reader.read() {
            if chunk.is_empty() {
                continue;
            }
            let len = chunk.len();
            match inbound.try_write(chunk) {
                Ok(()) => accepted += len,
                Err(_) => {
                    // finishing an Rx immediately removes it from self.inbound
                    // reaching this write means the Rx is unfinished, so an error means the slot is full
                    log::debug!("inbound backpressure: stream_id={stream_id} accepted={accepted}");
                    break;
                }
            }
        }

        if accepted > 0 {
            log::trace!("committed inbound bytes: stream_id={stream_id} accepted={accepted}");
            reader.commit_read(accepted).unwrap();
        }
        if finished && reader.readable_bytes() == 0 {
            inbound.finish();
            self.inbound = None;
        }
    }

    pub fn poll_outbound(&mut self, mut stream: StreamIo<'_>) {
        let stream_id = stream.stream_id();
        let Some(OutboundIo { tx, pending }) = &mut self.outbound else {
            return;
        };

        let mut writer = match stream.writer() {
            WriterState::Open(writer) => writer,
            WriterState::Finished => return,
            WriterState::Reset(code) => {
                self.outbound_fail(QlStreamError::StreamReset {
                    code,
                    origin: crate::ResetOrigin::Peer,
                });
                return;
            }
        };
        loop {
            let capacity = writer.capacity();
            log::trace!("stream write capacity: stream_id={stream_id} capacity={capacity}");
            if capacity == 0 {
                break;
            }

            let Ok(mut bytes) = tx.try_read(pending, capacity) else {
                break;
            };
            if bytes.is_empty() {
                break;
            }

            log::trace!(
                "writing stream bytes: stream_id={stream_id} len={}",
                bytes.len()
            );
            let _ = writer.write(&mut bytes);
            debug_assert!(
                bytes.is_empty(),
                "stream writer left {} bytes unwritten: stream_id={stream_id}",
                bytes.len()
            );
        }

        if pending.is_empty() && tx.is_finished() {
            log::info!("observed outbound writer finished: stream_id={stream_id}");
            writer.finish();
        }
    }
}

impl StreamMeta for DriverStreamIo {
    fn on_readable(&mut self, stream: StreamIo<'_>) {
        self.poll_inbound(stream);
    }

    fn on_writable(&mut self, stream: StreamIo<'_>) {
        self.poll_outbound(stream);
    }

    fn on_inbound_finished(&mut self, stream: StreamIo<'_>) {
        self.poll_inbound(stream);
    }

    fn on_outbound_finished(&mut self, _stream_id: ql_common::StreamId) {
        if let Some(outbound) = self.outbound.take() {
            outbound.tx.finish();
        }
    }

    fn on_reset(&mut self, reset: StreamResetEvent) {
        log::info!("stream reset: {reset:?}");
        if reset.origin == crate::ResetOrigin::Local {
            if reset.target.reader() {
                self.inbound = None;
            }
            if reset.target.writer() {
                self.outbound = None;
            }
            return;
        }
        let error = QlStreamError::StreamReset {
            code: reset.code,
            origin: reset.origin,
        };
        if reset.target.reader() {
            self.inbound_fail(error.clone());
        }
        if reset.target.writer() {
            self.outbound_fail(error);
        }
    }
}

impl Drop for DriverStreamIo {
    fn drop(&mut self) {
        self.inbound_fail(QlStreamError::NoSession);
        self.outbound_fail(QlStreamError::NoSession);
    }
}
