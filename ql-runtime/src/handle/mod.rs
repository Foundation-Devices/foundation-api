mod reader;
mod writer;

use ql_fsm::NoSessionError;
use ql_wire::{CloseTarget, PairingToken, PeerBundle, RouteId, StreamId};

pub use self::{reader::*, writer::*};
use crate::{chunk_slot, command::Command};

#[derive(Debug)]
pub struct QlStream {
    pub stream_id: StreamId,
    pub route_id: RouteId,
    pub writer: StreamWriter,
    pub reader: StreamReader,
}

#[derive(Clone)]
pub struct RuntimeHandle {
    tx: async_channel::Sender<Command>,
}

impl RuntimeHandle {
    /// binds the remote peer
    pub fn bind_peer(&self, peer: PeerBundle) {
        self.send(Command::BindPeer { peer });
    }

    /// starts an IK handshake with the bound peer
    pub fn connect(&self) {
        self.send(Command::Connect);
    }

    /// arms acceptance of inbound xx pairings for a single token
    pub fn arm_pairing(&self, token: PairingToken) {
        self.send(Command::ArmPairing { token });
    }

    /// disarms inbound xx pairing
    pub fn disarm_pairing(&self) {
        self.send(Command::DisarmPairing);
    }

    /// starts an outbound xx handshake using the supplied pairing token
    pub fn start_pairing(&self, token: PairingToken) {
        self.send(Command::StartPairing { token });
    }

    /// opens a new stream on the active encrypted session
    pub async fn open_stream(&self, route_id: RouteId) -> Result<QlStream, NoSessionError> {
        let (request_reader, request_writer) = chunk_slot::new();
        let (request_terminal_tx, request_terminal_rx) = oneshot::channel();
        let (start_tx, start_rx) = oneshot::channel();

        self.send(Command::OpenStream {
            route_id,
            request_reader,
            request_terminal: request_terminal_tx,
            start: start_tx,
        });

        // runtime cannot be shutdown while we have a handle
        let (stream_id, reader) = start_rx.await.unwrap()?;

        Ok(QlStream {
            stream_id,
            route_id,
            writer: StreamWriter::new(
                stream_id,
                CloseTarget::Origin,
                request_writer,
                request_terminal_rx,
                self.clone(),
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
    pub(crate) fn new(tx: async_channel::Sender<Command>) -> Self {
        Self { tx }
    }

    #[inline]
    #[track_caller]
    pub(crate) fn send(&self, cmd: Command) {
        self.tx.try_send(cmd).expect("runtime is alive");
    }

    pub(crate) fn try_send(&self, cmd: Command) -> bool {
        self.tx.try_send(cmd).is_ok()
    }
}
