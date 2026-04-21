use crate::{codec, ByteSlice, WireEncode, WireError};

/// Session parameters advertised in the handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportParams {
    /// Initial per-stream receive credit granted to the remote peer
    pub initial_stream_receive_window: u32,
}

impl TransportParams {
    pub const WIRE_SIZE: usize = size_of::<u32>();
}

impl WireEncode for TransportParams {
    fn encoded_len(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.initial_stream_receive_window.encode(out);
    }
}

impl Default for TransportParams {
    fn default() -> Self {
        Self {
            initial_stream_receive_window: 16 * 1024,
        }
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for TransportParams {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            initial_stream_receive_window: reader.decode()?,
        })
    }
}
