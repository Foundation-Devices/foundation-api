use ql_common::ResetCode;

use super::StreamId;

ql_codec::codec! {
    /// aborts one or both lanes of a stream with a reset code
    ///
    /// stream origin is the peer that opened the stream
    /// origin lane carries bytes sent by the stream origin
    /// return lane carries bytes sent back toward the stream origin
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StreamReset {
        pub stream_id: StreamId,
        pub target: ResetTarget,
        pub code: ResetCode,
    }
}

ql_codec::codec! {
    /// selects which stream lane a [`StreamReset`] applies to
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ResetTarget {
        /// reset the lane sent by the stream origin
        Origin = 1,
        /// reset the lane sent back toward the stream origin
        Return = 2,
        /// reset both stream lanes
        Both = 3,
    }
}
