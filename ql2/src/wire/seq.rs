use std::{cmp::Ordering, fmt};

use rkyv::{Archive, Deserialize, Serialize};

#[derive(
    Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
#[repr(transparent)]
pub struct StreamSeq(pub u32);

impl fmt::Display for StreamSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&ArchivedStreamSeq> for StreamSeq {
    fn from(value: &ArchivedStreamSeq) -> Self {
        Self(value.0.to_native())
    }
}

impl StreamSeq {
    const HALF_RANGE: u32 = 1 << 31;
    pub const START: Self = Self(1);

    pub fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    pub fn prev(self) -> Self {
        Self(self.0.wrapping_sub(1))
    }

    pub fn add(self, delta: u32) -> Self {
        Self(self.0.wrapping_add(delta))
    }

    pub fn serial_cmp(self, other: Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }

        let delta = self.0.wrapping_sub(other.0);
        if delta < Self::HALF_RANGE {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }

    pub fn serial_lt(self, other: Self) -> bool {
        self.serial_cmp(other) == Ordering::Less
    }

    pub fn serial_lte(self, other: Self) -> bool {
        !self.serial_gt(other)
    }

    pub fn serial_gt(self, other: Self) -> bool {
        self.serial_cmp(other) == Ordering::Greater
    }

    pub fn forward_distance_to(self, other: Self) -> Option<u32> {
        match other.serial_cmp(self) {
            Ordering::Less => None,
            Ordering::Equal => Some(0),
            Ordering::Greater => Some(other.0.wrapping_sub(self.0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_seq_serial_order_wraps() {
        assert!(StreamSeq(0).serial_gt(StreamSeq(u32::MAX)));
        assert!(StreamSeq(1).serial_gt(StreamSeq(u32::MAX)));
        assert!(StreamSeq(u32::MAX).serial_lt(StreamSeq(0)));
        assert!(StreamSeq(u32::MAX - 1).serial_lt(StreamSeq(1)));
    }

    #[test]
    fn stream_seq_forward_distance_wraps() {
        assert_eq!(
            StreamSeq(u32::MAX - 1).forward_distance_to(StreamSeq(1)),
            Some(3)
        );
        assert_eq!(
            StreamSeq(u32::MAX).forward_distance_to(StreamSeq(2)),
            Some(3)
        );
        assert_eq!(StreamSeq(1).forward_distance_to(StreamSeq(u32::MAX)), None);
    }
}
