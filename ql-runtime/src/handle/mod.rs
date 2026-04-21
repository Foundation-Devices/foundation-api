use ql_fsm::NoSessionError;
use ql_wire::{PairingToken, PeerBundle, RouteId, SessionCloseCode, StreamId};

use crate::command::Command;
pub use crate::io::{StreamReader, StreamWriter};

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

    /// closes the current encrypted session
    pub fn close_session(&self, code: SessionCloseCode) {
        self.send(Command::CloseSession { code });
    }

    /// forgets the currently bound peer and initiates session unpairing if connected
    pub fn unpair(&self) {
        self.send(Command::Unpair);
    }

    /// opens a new stream on the active encrypted session
    pub async fn open_stream(&self, route_id: RouteId) -> Result<QlStream, NoSessionError> {
        let (start_tx, start_rx) = oneshot::channel();

        self.send(Command::OpenStream {
            route_id,
            start: start_tx,
        });

        // runtime cannot be shutdown while we have a handle
        let (stream_id, reader, writer) = start_rx.await.unwrap()?;

        Ok(QlStream {
            stream_id,
            route_id,
            writer,
            reader,
        })
    }

    #[cfg(feature = "rpc")]
    pub fn rpc(&self) -> crate::rpc::RpcHandle {
        crate::rpc::RpcHandle::new(self.clone())
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
