mod reader;
mod writer;

use ql_wire::{CloseTarget, PeerBundle, StreamId};

pub use self::{reader::*, writer::*};
use crate::{command::RuntimeCommand, QlError};

#[derive(Debug)]
pub struct QlStream {
    pub stream_id: StreamId,
    pub writer: ByteWriter,
    pub reader: ByteReader,
}

#[derive(Clone)]
pub struct RuntimeHandle {
    tx: async_channel::Sender<RuntimeCommand>,
    stream_send_buffer_bytes: usize,
}

impl RuntimeHandle {
    pub fn bind_peer(&self, peer: PeerBundle) {
        self.send(RuntimeCommand::BindPeer { peer });
    }

    pub fn connect(&self) {
        self.send(RuntimeCommand::Connect)
    }

    pub fn send_incoming(&self, bytes: Vec<u8>) {
        self.send(RuntimeCommand::Incoming(bytes));
    }

    pub async fn open_stream(&self) -> Result<QlStream, QlError> {
        let (request_reader, request_writer) = piper::pipe(self.stream_send_buffer_bytes);
        let (start_tx, start_rx) = oneshot::channel();

        self.send(RuntimeCommand::OpenStream {
            request_reader,
            start: start_tx,
        });
        // runtime cannot be shutdown while we have a handle
        let (stream_id, reader) = start_rx.await.unwrap()?;

        Ok(QlStream {
            stream_id,
            writer: ByteWriter::new(
                stream_id,
                CloseTarget::Origin,
                request_writer,
                self.tx.clone(),
            ),
            reader,
        })
    }

    #[cfg(feature = "rpc")]
    pub fn rpc(&self) -> crate::rpc::RpcHandle {
        crate::rpc::RpcHandle {
            inner: self.clone(),
        }
    }
}

impl RuntimeHandle {
    pub(crate) fn new(
        tx: async_channel::Sender<RuntimeCommand>,
        stream_send_buffer_bytes: usize,
    ) -> Self {
        Self {
            tx,
            stream_send_buffer_bytes,
        }
    }

    #[inline]
    #[track_caller]
    fn send(&self, cmd: RuntimeCommand) {
        self.tx.send_blocking(cmd).expect("runtime is alive");
    }
}
