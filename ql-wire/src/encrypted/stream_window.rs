use ql_codec::Varint;

use super::StreamId;

ql_codec::codec! {
    /// advertises the highest byte offset the peer may send on a stream.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StreamWindow {
        pub stream_id: StreamId,
        pub maximum_offset: Varint<u64>,
    }
}
