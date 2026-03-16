pub type StreamStore = crate::stream::StreamFsm;

pub use crate::stream::internal::{
    BufferIncomingResult, InFlightFrame, InFlightWriteState, InboundState, InitiatorStream,
    OutboundPhase, StreamControl, StreamRole, StreamState,
};
