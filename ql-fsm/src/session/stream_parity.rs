use ql_wire::{StreamId, XID};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamParity {
    Even,
    Odd,
}

impl StreamParity {
    pub fn for_local(local: XID, peer: XID) -> Self {
        match local.0.cmp(&peer.0) {
            std::cmp::Ordering::Less | std::cmp::Ordering::Equal => Self::Even,
            std::cmp::Ordering::Greater => Self::Odd,
        }
    }

    pub const fn first_stream_id(self) -> u32 {
        match self {
            Self::Even => 0,
            Self::Odd => 1,
        }
    }

    pub const fn matches(self, stream_id: StreamId) -> bool {
        match self {
            Self::Even => stream_id.0 % 2 == 0,
            Self::Odd => stream_id.0 % 2 == 1,
        }
    }

    pub const fn remote(self) -> Self {
        match self {
            Self::Even => Self::Odd,
            Self::Odd => Self::Even,
        }
    }

    pub fn make_stream_id(self, ordinal: u32) -> StreamId {
        StreamId(
            self.first_stream_id()
                .saturating_add(ordinal.saturating_mul(2)),
        )
    }
}
