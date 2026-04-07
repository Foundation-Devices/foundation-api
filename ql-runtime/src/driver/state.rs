use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use ql_fsm::QlFsmEvent;
use ql_wire::{CloseTarget, StreamId};

use crate::{
    chunk_slot::{ChunkSlotRx, ChunkSlotTx, TrySendError},
    command::RuntimeCommand,
    QlStreamError,
};

pub struct DriverState {
    pub streams: HashMap<StreamId, DriverStreamIo>,
    pub runtime_tx: async_channel::WeakSender<RuntimeCommand>,
    pub max_concurrent_message_writes: usize,
    pub pending_fsm_events: VecDeque<QlFsmEvent>,
}

pub struct DriverStreamIo {
    is_initiator: bool,
    outbound: Option<OutboundIo>,
    inbound: Option<InboundIo>,
}

impl DriverStreamIo {
    pub fn new(
        is_initiator: bool,
        outbound: Option<OutboundIo>,
        inbound: Option<InboundIo>,
    ) -> Self {
        Self {
            is_initiator,
            outbound,
            inbound,
        }
    }

    pub fn inbound_target(&self) -> CloseTarget {
        if self.is_initiator {
            CloseTarget::Return
        } else {
            CloseTarget::Origin
        }
    }

    pub fn outbound_target(&self) -> CloseTarget {
        if self.is_initiator {
            CloseTarget::Origin
        } else {
            CloseTarget::Return
        }
    }

    pub fn fail_all(&mut self) {
        self.inbound_fail(QlStreamError::NoSession);
        self.outbound_fail(QlStreamError::NoSession);
    }

    pub fn is_closed(&self) -> bool {
        self.outbound.is_none() && self.inbound.is_none()
    }

    pub fn outbound_close(&mut self) {
        self.outbound = None;
    }

    pub fn outbound_fail(&mut self, error: QlStreamError) {
        if let Some(mut outbound) = self.outbound.take() {
            if let Some(terminal) = outbound.terminal.take() {
                let _ = terminal.send(error);
            }
        }
    }

    pub fn outbound_reader_mut(&mut self) -> Option<&mut ChunkSlotRx> {
        self.outbound.as_mut().map(|outbound| &mut outbound.reader)
    }

    pub fn inbound_close(&mut self) {
        self.inbound = None;
    }

    pub fn inbound_try_write(&mut self, bytes: Bytes) -> InboundWriteResult {
        let Some(inbound) = self.inbound.as_mut() else {
            return InboundWriteResult::Closed;
        };

        let len = bytes.len();
        match inbound.writer.try_send(bytes) {
            Ok(()) => InboundWriteResult::Accepted(len),
            Err(TrySendError::Full(_)) => InboundWriteResult::Full,
            Err(TrySendError::Closed(_)) => {
                self.inbound = None;
                InboundWriteResult::Closed
            }
        }
    }

    pub fn inbound_finish(&mut self) {
        if let Some(mut inbound) = self.inbound.take() {
            inbound.writer.close();
            if let Some(terminal) = inbound.terminal.take() {
                let _ = terminal.send(Ok(()));
            }
        }
    }

    pub fn inbound_fail(&mut self, error: QlStreamError) {
        if let Some(mut inbound) = self.inbound.take() {
            inbound.writer.close();
            if let Some(terminal) = inbound.terminal.take() {
                let _ = terminal.send(Err(error));
            }
        }
    }

    pub fn inbound_queue_finish(&mut self) {
        if let Some(inbound) = self.inbound.as_mut() {
            inbound.finish_pending = true;
        }
    }

    pub fn inbound_finish_pending(&self) -> bool {
        self.inbound
            .as_ref()
            .is_some_and(|inbound| inbound.finish_pending)
    }
}

pub struct OutboundIo {
    reader: ChunkSlotRx,
    terminal: Option<oneshot::Sender<QlStreamError>>,
}

impl OutboundIo {
    pub fn new(reader: ChunkSlotRx, terminal: oneshot::Sender<QlStreamError>) -> Self {
        Self {
            reader,
            terminal: Some(terminal),
        }
    }
}

pub struct InboundIo {
    writer: ChunkSlotTx,
    terminal: Option<oneshot::Sender<Result<(), QlStreamError>>>,
    finish_pending: bool,
}

pub enum InboundWriteResult {
    Accepted(usize),
    Full,
    Closed,
}

impl InboundIo {
    pub fn new(writer: ChunkSlotTx, terminal: oneshot::Sender<Result<(), QlStreamError>>) -> Self {
        Self {
            writer,
            terminal: Some(terminal),
            finish_pending: false,
        }
    }
}
