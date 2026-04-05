mod reader;
mod writer;

use ql_wire::{CloseTarget, PeerBundle, StreamId};

pub use self::{reader::*, writer::*};
use crate::{command::RuntimeCommand, OpenedStreamDelivery, QlError};

#[derive(Debug)]
pub struct QlStream {
    pub stream_id: StreamId,
    pub writer: ByteWriter,
    pub reader: ByteReader,
}

#[derive(Clone)]
pub struct RuntimeHandle {
    pub(crate) tx: async_channel::Sender<RuntimeCommand>,
    pub(crate) stream_send_buffer_bytes: usize,
}

impl RuntimeHandle {
    pub fn bind_peer(&self, peer: PeerBundle) {
        self.send(RuntimeCommand::BindPeer { peer })
    }

    pub fn connect(&self) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeCommand::Connect)
            .map_err(|_| QlError::Cancelled)
    }

    pub fn send_incoming(&self, bytes: Vec<u8>) {
        self.send(RuntimeCommand::Incoming(bytes))
    }

    pub async fn open_stream(&self) -> Result<QlStream, QlError> {
        let (request_reader, request_writer) = piper::pipe(self.stream_send_buffer_bytes);
        let (start_tx, start_rx) = oneshot::channel();

        self.tx
            .send(RuntimeCommand::OpenStream {
                request_reader,
                start: start_tx,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;

        let OpenedStreamDelivery { stream_id, reader } =
            start_rx.await.unwrap_or(Err(QlError::Cancelled))?;

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
    #[inline]
    #[track_caller]
    fn send(&self, cmd: RuntimeCommand) {
        self.tx.send_blocking(cmd).expect("runtime is alive")
    }
}
