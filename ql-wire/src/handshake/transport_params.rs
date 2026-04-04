use crate::{codec, ByteSlice, WireError};

/// Session parameters advertised in the handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportParams {
    /// Initial per-stream receive credit granted to the remote peer
    pub initial_stream_receive_window: u32,
}

impl TransportParams {
    pub const WIRE_SIZE: usize = size_of::<u32>();

    pub fn encode_into<'a>(&self, out: &'a mut [u8]) -> &'a mut [u8] {
        codec::write_u32(out, self.initial_stream_receive_window)
    }

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut out = [0; Self::WIRE_SIZE];
        let _ = self.encode_into(&mut out);
        out
    }
}

impl Default for TransportParams {
    fn default() -> Self {
        Self {
            initial_stream_receive_window: 16 * 1024,
        }
    }
}

impl<B: ByteSlice> codec::WireParse<B> for TransportParams {
    fn parse(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            initial_stream_receive_window: reader.take_u32()?,
        })
    }
}
