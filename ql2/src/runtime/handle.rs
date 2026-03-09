use async_channel::Sender;
use bc_components::{MLDSAPublicKey, MLKEMPublicKey, XID};

use crate::{
    runtime::{
        internal::{InboundStreamItem, OutboundStreamInput, RuntimeCommand},
        AcceptedCallDelivery, CallConfig,
    },
    wire::call::{Direction, RejectCode, ResetCode},
    CallId, QlError, RouteId,
};

#[derive(Clone)]
pub struct RuntimeHandle {
    pub(crate) tx: async_channel::Sender<RuntimeCommand>,
}

pub struct PendingCall {
    pub request: OutboundByteStream,
    pub accepted: PendingAccept,
}

pub struct PendingAccept {
    rx: oneshot::Receiver<Result<AcceptedCallDelivery, QlError>>,
}

#[derive(Debug)]
pub struct AcceptedCall {
    pub call_id: CallId,
    pub response_head: Vec<u8>,
    pub response: InboundByteStream,
}

#[derive(Debug)]
pub struct InboundCall {
    pub sender: XID,
    pub recipient: XID,
    pub route_id: RouteId,
    pub call_id: CallId,
    pub request_head: Vec<u8>,
    pub response_expected: bool,
    pub request: InboundByteStream,
    pub respond_to: CallResponder,
}

#[derive(Debug, Clone)]
pub struct CallResponder {
    call_id: CallId,
    recipient: XID,
    tx: async_channel::Sender<RuntimeCommand>,
}

pub struct InboundByteStream {
    sender: XID,
    call_id: CallId,
    dir: Direction,
    rx: async_channel::Receiver<InboundStreamItem>,
    tx: Sender<RuntimeCommand>,
    finished: bool,
}

impl std::fmt::Debug for InboundByteStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundByteStream")
            .field("sender", &self.sender)
            .field("call_id", &self.call_id)
            .field("dir", &self.dir)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

pub struct OutboundByteStream {
    recipient: XID,
    call_id: CallId,
    dir: Direction,
    chunk_tx: Option<Sender<OutboundStreamInput>>,
    tx: Sender<RuntimeCommand>,
}

impl PendingAccept {
    pub async fn recv(self) -> Result<AcceptedCall, QlError> {
        let delivery = self.rx.await.unwrap_or(Err(QlError::Cancelled))?;
        let AcceptedCallDelivery {
            peer,
            call_id,
            response_head,
            rx,
            tx,
        } = delivery;
        Ok(AcceptedCall {
            call_id,
            response_head,
            response: InboundByteStream::new(peer, call_id, Direction::Response, rx, tx),
        })
    }
}

impl InboundByteStream {
    pub(crate) fn new(
        sender: XID,
        call_id: CallId,
        dir: Direction,
        rx: async_channel::Receiver<InboundStreamItem>,
        tx: Sender<RuntimeCommand>,
    ) -> Self {
        Self {
            sender,
            call_id,
            dir,
            rx,
            tx,
            finished: false,
        }
    }

    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, QlError> {
        if self.finished {
            return Ok(None);
        }
        match self.rx.recv().await {
            Ok(InboundStreamItem::Chunk(chunk)) => {
                let len = chunk.len();
                let _ = self
                    .tx
                    .send(RuntimeCommand::AdvanceInboundCredit {
                        sender: self.sender,
                        call_id: self.call_id,
                        dir: self.dir,
                        amount: len as u64,
                    })
                    .await;
                Ok(Some(chunk))
            }
            Ok(InboundStreamItem::Finished) => {
                self.finished = true;
                Ok(None)
            }
            Ok(InboundStreamItem::Error(error)) => {
                self.finished = true;
                Err(error)
            }
            Err(_) => {
                self.finished = true;
                Err(QlError::Cancelled)
            }
        }
    }

    pub async fn reset(mut self, code: ResetCode) -> Result<(), QlError> {
        self.finished = true;
        self.tx
            .send(RuntimeCommand::ResetInbound {
                sender: self.sender,
                call_id: self.call_id,
                dir: self.dir,
                code,
            })
            .await
            .map_err(|_| QlError::Cancelled)
    }
}

impl Drop for InboundByteStream {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self.tx.try_send(RuntimeCommand::ResetInbound {
            sender: self.sender,
            call_id: self.call_id,
            dir: self.dir,
            code: ResetCode::Cancelled,
        });
    }
}

impl OutboundByteStream {
    pub(crate) fn new(
        recipient: XID,
        call_id: CallId,
        dir: Direction,
        chunk_tx: Sender<OutboundStreamInput>,
        tx: Sender<RuntimeCommand>,
    ) -> Self {
        Self {
            recipient,
            call_id,
            dir,
            chunk_tx: Some(chunk_tx),
            tx,
        }
    }

    pub async fn write_next(&mut self, chunk: Vec<u8>) -> Result<(), QlError> {
        let chunk_tx = self
            .chunk_tx
            .as_ref()
            .expect("stream not finished or reset");
        chunk_tx
            .send(OutboundStreamInput::Chunk(chunk))
            .await
            .map_err(|_| QlError::Cancelled)?;
        self.tx
            .send(RuntimeCommand::PollCall {
                peer: self.recipient,
                call_id: self.call_id,
            })
            .await
            .map_err(|_| QlError::Cancelled)
    }

    pub async fn finish(mut self) -> Result<(), QlError> {
        let Some(chunk_tx) = self.chunk_tx.take() else {
            return Ok(());
        };
        if chunk_tx.send(OutboundStreamInput::Finish).await.is_err() {
            return Ok(());
        }
        self.tx
            .send(RuntimeCommand::PollCall {
                peer: self.recipient,
                call_id: self.call_id,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;
        chunk_tx.closed().await;
        Ok(())
    }

    pub async fn reset(mut self, code: ResetCode) -> Result<(), QlError> {
        self.chunk_tx.take();
        self.tx
            .send(RuntimeCommand::ResetOutbound {
                recipient: self.recipient,
                call_id: self.call_id,
                dir: self.dir,
                code,
            })
            .await
            .map_err(|_| QlError::Cancelled)
    }
}

impl Drop for OutboundByteStream {
    fn drop(&mut self) {
        if self.chunk_tx.take().is_none() {
            return;
        }
        let _ = self.tx.try_send(RuntimeCommand::ResetOutbound {
            recipient: self.recipient,
            call_id: self.call_id,
            dir: self.dir,
            code: ResetCode::Cancelled,
        });
    }
}

impl CallResponder {
    pub(crate) fn new(
        call_id: CallId,
        recipient: XID,
        tx: async_channel::Sender<RuntimeCommand>,
    ) -> Self {
        Self {
            call_id,
            recipient,
            tx,
        }
    }

    pub fn accept(self, response_head: Vec<u8>) -> Result<OutboundByteStream, QlError> {
        let (chunk_tx, chunk_rx) = async_channel::bounded(1);
        self.tx
            .send_blocking(RuntimeCommand::AcceptCall {
                recipient: self.recipient,
                call_id: self.call_id,
                response_head,
                response_rx: chunk_rx,
            })
            .map_err(|_| QlError::Cancelled)?;
        Ok(OutboundByteStream::new(
            self.recipient,
            self.call_id,
            Direction::Response,
            chunk_tx,
            self.tx,
        ))
    }

    pub fn reject(self, code: RejectCode) -> Result<(), QlError> {
        self.tx
            .try_send(RuntimeCommand::RejectCall {
                recipient: self.recipient,
                call_id: self.call_id,
                code,
            })
            .map_err(|_| QlError::Cancelled)
    }
}

impl RuntimeHandle {
    pub fn register_peer(
        &self,
        peer: XID,
        signing_key: MLDSAPublicKey,
        encapsulation_key: MLKEMPublicKey,
    ) {
        self.send(RuntimeCommand::RegisterPeer {
            peer,
            signing_key,
            encapsulation_key,
        })
    }

    pub fn connect(&self, peer: XID) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeCommand::Connect { peer })
            .map_err(|_| QlError::Cancelled)
    }

    pub fn unpair(&self, peer: XID) -> Result<(), QlError> {
        self.tx
            .send_blocking(RuntimeCommand::Unpair { peer })
            .map_err(|_| QlError::Cancelled)
    }

    pub fn send_incoming(&self, bytes: Vec<u8>) {
        self.send(RuntimeCommand::Incoming(bytes))
    }

    pub async fn open_call(
        &self,
        recipient: XID,
        route_id: RouteId,
        request_head: Vec<u8>,
        response_expected: bool,
        config: CallConfig,
    ) -> Result<PendingCall, QlError> {
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (chunk_tx, chunk_rx) = async_channel::bounded(1);
        let (start_tx, start_rx) = oneshot::channel();
        self.tx
            .send(RuntimeCommand::OpenCall {
                recipient,
                route_id,
                request_head,
                response_expected,
                request_rx: chunk_rx,
                accepted: accepted_tx,
                start: start_tx,
                config,
            })
            .await
            .map_err(|_| QlError::Cancelled)?;

        let call_id = start_rx.await.unwrap_or(Err(QlError::Cancelled))?;

        Ok(PendingCall {
            request: OutboundByteStream::new(
                recipient,
                call_id,
                Direction::Request,
                chunk_tx,
                self.tx.clone(),
            ),
            accepted: PendingAccept { rx: accepted_rx },
        })
    }
}

impl RuntimeHandle {
    #[inline]
    #[track_caller]
    fn send(&self, cmd: RuntimeCommand) {
        self.tx.send_blocking(cmd).expect("runtime is alive")
    }
}
