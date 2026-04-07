use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use ql_fsm::QlFsmEvent;
use ql_wire::{CloseTarget, StreamId, XID};

use crate::{
    chunk_slot::{ChunkSlotRx, ChunkSlotTx, TrySendError},
    command::RuntimeCommand,
    QlStreamError,
};

pub struct DriverState {
    pub streams: HashMap<StreamId, DriverStreamIo>,
    pub runtime_tx: async_channel::WeakSender<RuntimeCommand>,
    pub max_concurrent_message_writes: usize,
    pub peer_xid: Option<XID>,
    pub pending_fsm_events: VecDeque<QlFsmEvent>,
}

pub struct DriverStreamIo {
    is_initiator: bool,
    outbound: OutboundIo,
    inbound: InboundIo,
}

impl DriverStreamIo {
    #[cfg(test)]
    pub fn new(is_initiator: bool, outbound: OutboundIo, inbound: InboundIo) -> Self {
        Self {
            is_initiator,
            outbound,
            inbound,
        }
    }

    pub fn new_initiator(
        request: ChunkSlotRx,
        request_terminal: oneshot::Sender<QlStreamError>,
        response: ChunkSlotTx,
        response_terminal: oneshot::Sender<Result<(), QlStreamError>>,
    ) -> Self {
        Self {
            is_initiator: true,
            outbound: OutboundIo::new(request, request_terminal),
            inbound: InboundIo::new(response, response_terminal),
        }
    }

    pub fn new_responder(
        request: ChunkSlotTx,
        request_terminal: oneshot::Sender<Result<(), QlStreamError>>,
        response: ChunkSlotRx,
        response_terminal: oneshot::Sender<QlStreamError>,
    ) -> Self {
        Self {
            is_initiator: false,
            outbound: OutboundIo::new(response, response_terminal),
            inbound: InboundIo::new(request, request_terminal),
        }
    }

    pub fn outbound_mut(&mut self) -> &mut OutboundIo {
        &mut self.outbound
    }

    pub fn inbound_mut(&mut self) -> &mut InboundIo {
        &mut self.inbound
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
        if self.is_initiator {
            self.outbound.fail(QlStreamError::SessionClosed);
            self.inbound.fail(QlStreamError::SessionClosed);
        } else {
            self.inbound.fail(QlStreamError::SessionClosed);
            self.outbound.fail(QlStreamError::SessionClosed);
        }
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.outbound, OutboundIo::Closed) && matches!(self.inbound, InboundIo::Closed)
    }
}

pub enum OutboundIo {
    Open {
        reader: ChunkSlotRx,
        terminal: Option<oneshot::Sender<QlStreamError>>,
    },
    Closed,
}

impl OutboundIo {
    pub fn new(reader: ChunkSlotRx, terminal: oneshot::Sender<QlStreamError>) -> Self {
        Self::Open {
            reader,
            terminal: Some(terminal),
        }
    }

    pub fn close(&mut self) {
        *self = Self::Closed;
    }

    pub fn fail(&mut self, error: QlStreamError) {
        if let Self::Open { mut terminal, .. } = std::mem::replace(self, Self::Closed) {
            if let Some(terminal) = terminal.take() {
                let _ = terminal.send(error);
            }
        }
    }

    pub fn open_mut(&mut self) -> Option<&mut ChunkSlotRx> {
        match self {
            Self::Open { reader, .. } => Some(reader),
            Self::Closed => None,
        }
    }
}

pub enum InboundIo {
    Open {
        writer: ChunkSlotTx,
        terminal: Option<oneshot::Sender<Result<(), QlStreamError>>>,
        finish_pending: bool,
    },
    Closed,
}

pub enum InboundWriteResult {
    Accepted(usize),
    Full,
    Closed,
}

impl InboundIo {
    pub fn new(writer: ChunkSlotTx, terminal: oneshot::Sender<Result<(), QlStreamError>>) -> Self {
        Self::Open {
            writer,
            terminal: Some(terminal),
            finish_pending: false,
        }
    }

    pub fn close(&mut self) {
        *self = Self::Closed;
    }

    pub fn try_write(&mut self, bytes: Bytes) -> InboundWriteResult {
        let Self::Open { writer, .. } = self else {
            return InboundWriteResult::Closed;
        };

        let len = bytes.len();
        match writer.try_send(bytes) {
            Ok(()) => InboundWriteResult::Accepted(len),
            Err(TrySendError::Full(_)) => InboundWriteResult::Full,
            Err(TrySendError::Closed(_)) => {
                *self = Self::Closed;
                InboundWriteResult::Closed
            }
        }
    }

    pub fn finish(&mut self) {
        if let Self::Open {
            mut terminal,
            writer,
            ..
        } = std::mem::replace(self, Self::Closed)
        {
            writer.close();
            if let Some(terminal) = terminal.take() {
                let _ = terminal.send(Ok(()));
            }
        }
    }

    pub fn fail(&mut self, error: QlStreamError) {
        if let Self::Open {
            mut terminal,
            writer,
            ..
        } = std::mem::replace(self, Self::Closed)
        {
            writer.close();
            if let Some(terminal) = terminal.take() {
                let _ = terminal.send(Err(error));
            }
        }
    }

    pub fn queue_finish(&mut self) {
        if let Self::Open { finish_pending, .. } = self {
            *finish_pending = true;
        }
    }

    pub fn finish_pending(&self) -> bool {
        match self {
            Self::Open { finish_pending, .. } => *finish_pending,
            Self::Closed => false,
        }
    }
}
