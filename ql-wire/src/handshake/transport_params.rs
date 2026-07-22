ql_codec::codec! {
    /// Session parameters advertised in the handshake
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TransportParams {
        /// Initial per-stream receive credit granted to the remote peer
        pub initial_stream_receive_window: u32,
    }
}

impl Default for TransportParams {
    fn default() -> Self {
        Self {
            initial_stream_receive_window: 16 * 1024,
        }
    }
}
