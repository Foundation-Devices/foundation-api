use std::collections::{HashMap, VecDeque};

use ql_fsm::QlFsmEvent;
use ql_wire::{CloseTarget, StreamId, XID};

use crate::{command::RuntimeCommand, QlError};

pub struct DriverState {
    pub streams: HashMap<StreamId, DriverStreamIo>,
    pub runtime_tx: async_channel::Sender<RuntimeCommand>,
    pub stream_send_buffer_bytes: usize,
    pub max_concurrent_message_writes: usize,
    pub peer_xid: Option<XID>,
    pub pending_fsm_events: VecDeque<QlFsmEvent>,
}

pub enum DriverStreamIo {
    Initiator {
        request: OutboundIo,
        response: InboundIo,
    },
    Responder {
        request: InboundIo,
        response: OutboundIo,
    },
}

impl DriverStreamIo {
    pub fn new_initiator(
        request: piper::Reader,
        response: piper::Writer,
        response_terminal: oneshot::Sender<Result<(), QlError>>,
    ) -> Self {
        Self::Initiator {
            request: OutboundIo::new(request),
            response: InboundIo::new(response, response_terminal),
        }
    }

    pub fn new_responder(
        request: piper::Writer,
        request_terminal: oneshot::Sender<Result<(), QlError>>,
        response: piper::Reader,
    ) -> Self {
        Self::Responder {
            request: InboundIo::new(request, request_terminal),
            response: OutboundIo::new(response),
        }
    }

    pub fn outbound_mut(&mut self) -> &mut OutboundIo {
        match self {
            Self::Initiator { request, .. } => request,
            Self::Responder { response, .. } => response,
        }
    }

    pub fn inbound_mut(&mut self) -> &mut InboundIo {
        match self {
            Self::Initiator { response, .. } => response,
            Self::Responder { request, .. } => request,
        }
    }

    pub fn inbound_target(&self) -> CloseTarget {
        match self {
            Self::Initiator { .. } => CloseTarget::Return,
            Self::Responder { .. } => CloseTarget::Origin,
        }
    }

    pub fn outbound_target(&self) -> CloseTarget {
        match self {
            Self::Initiator { .. } => CloseTarget::Origin,
            Self::Responder { .. } => CloseTarget::Return,
        }
    }

    pub fn fail_all(&mut self, error: QlError) {
        match self {
            Self::Initiator {
                request, response, ..
            } => {
                request.close();
                response.fail(error);
            }
            Self::Responder {
                request, response, ..
            } => {
                request.fail(error);
                response.close();
            }
        }
    }
}

pub enum OutboundIo {
    Open {
        reader: piper::Reader,
        finish_queued: bool,
    },
    Closed,
}

impl OutboundIo {
    pub fn new(reader: piper::Reader) -> Self {
        Self::Open {
            reader,
            finish_queued: false,
        }
    }

    pub fn close(&mut self) {
        *self = Self::Closed;
    }

    pub fn open_mut(&mut self) -> Option<(&mut piper::Reader, &mut bool)> {
        match self {
            Self::Open {
                reader,
                finish_queued,
            } => Some((reader, finish_queued)),
            Self::Closed => None,
        }
    }
}

pub enum InboundIo {
    Open {
        writer: piper::Writer,
        terminal: Option<oneshot::Sender<Result<(), QlError>>>,
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
    pub fn new(writer: piper::Writer, terminal: oneshot::Sender<Result<(), QlError>>) -> Self {
        Self::Open {
            writer,
            terminal: Some(terminal),
            finish_pending: false,
        }
    }

    pub fn close(&mut self) {
        *self = Self::Closed;
    }

    pub fn try_write(&mut self, bytes: &[u8]) -> InboundWriteResult {
        let Self::Open { writer, .. } = self else {
            return InboundWriteResult::Closed;
        };

        let accepted = writer.try_fill(bytes);
        if accepted > 0 {
            return InboundWriteResult::Accepted(accepted);
        }
        if writer.is_closed() {
            *self = Self::Closed;
            return InboundWriteResult::Closed;
        }
        InboundWriteResult::Full
    }

    pub fn finish(&mut self) {
        if let Self::Open { terminal, .. } = self {
            if let Some(terminal) = terminal.take() {
                let _ = terminal.send(Ok(()));
            }
        }
        *self = Self::Closed;
    }

    pub fn fail(&mut self, error: QlError) {
        if let Self::Open { terminal, .. } = self {
            if let Some(terminal) = terminal.take() {
                let _ = terminal.send(Err(error));
            }
        }
        *self = Self::Closed;
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
