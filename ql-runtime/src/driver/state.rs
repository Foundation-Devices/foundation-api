use std::collections::HashMap;

use bytes::Bytes;
use ql_wire::{CloseTarget, StreamId};

use crate::{
    command::Command,
    io::{PushError, ReaderIo, WriterIo},
    QlStreamError,
};

pub struct DriverState {
    pub streams: HashMap<StreamId, DriverStreamIo>,
    pub runtime_tx: async_channel::WeakSender<Command>,
    pub max_concurrent_message_writes: usize,
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

    pub fn outbound_finish(&mut self) {
        if let Some(outbound) = self.outbound.take() {
            outbound.writer.finish();
        }
    }

    pub fn outbound_fail(&mut self, error: QlStreamError) {
        if let Some(outbound) = self.outbound.take() {
            let _ = outbound.writer.fail(error);
        }
    }

    pub fn outbound_writer_mut(&mut self) -> Option<&mut WriterIo> {
        self.outbound.as_mut().map(|outbound| &mut outbound.writer)
    }

    pub fn outbound_queue_finish(&mut self) {
        if let Some(outbound) = self.outbound.as_mut() {
            outbound.finish_pending = true;
        }
    }

    pub fn outbound_finish_pending(&self) -> bool {
        self.outbound
            .as_ref()
            .is_some_and(|outbound| outbound.finish_pending)
    }

    pub fn inbound_close(&mut self) {
        self.inbound = None;
    }

    pub fn inbound_try_write(&mut self, bytes: Bytes) -> InboundWriteResult {
        let Some(inbound) = self.inbound.as_mut() else {
            return InboundWriteResult::Closed;
        };

        let len = bytes.len();
        match inbound.reader.try_write(bytes) {
            Ok(()) => InboundWriteResult::Accepted(len),
            Err(PushError::Full(_)) => InboundWriteResult::Full,
            Err(PushError::Closed(_)) => {
                self.inbound = None;
                InboundWriteResult::Closed
            }
        }
    }

    pub fn inbound_finish(&mut self) {
        if let Some(inbound) = self.inbound.take() {
            inbound.reader.finish();
        }
    }

    pub fn inbound_fail(&mut self, error: QlStreamError) {
        if let Some(inbound) = self.inbound.take() {
            let _ = inbound.reader.fail(error);
        }
    }
}

pub struct OutboundIo {
    writer: WriterIo,
    finish_pending: bool,
}

impl OutboundIo {
    pub fn new(writer: WriterIo) -> Self {
        Self {
            writer,
            finish_pending: false,
        }
    }
}

pub struct InboundIo {
    reader: ReaderIo,
}

pub enum InboundWriteResult {
    Accepted(usize),
    Full,
    Closed,
}

impl InboundIo {
    pub fn new(reader: ReaderIo) -> Self {
        Self { reader }
    }
}
