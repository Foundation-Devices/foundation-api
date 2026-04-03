use crate::{codec, RecordSeq, WireError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordAck {
    pub base_seq: RecordSeq,
    pub bits: u64,
}

impl RecordAck {
    pub const BITMAP_BITS: usize = u64::BITS as usize;
    pub const ENCODED_LEN: usize = size_of::<u64>() + size_of::<u64>();

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = codec::Reader::new(bytes);
        Ok(Self {
            base_seq: RecordSeq(reader.take_u64()?),
            bits: reader.take_u64()?,
        })
    }

    pub fn contains(&self, seq: u64) -> bool {
        if seq < self.base_seq.0 {
            return false;
        }

        let offset = seq - self.base_seq.0;
        if offset >= Self::BITMAP_BITS as u64 {
            return false;
        }

        (self.bits & (1u64 << offset)) != 0
    }

    pub fn encode_into(&self, out: &mut [u8]) {
        assert_eq!(out.len(), Self::ENCODED_LEN);
        let out = codec::write_u64(out, self.base_seq.0);
        let _ = codec::write_u64(out, self.bits);
    }
}

#[cfg(test)]
mod tests {
    use super::RecordAck;
    use crate::RecordSeq;

    #[test]
    fn encode_decode_round_trip() {
        let ack = RecordAck {
            base_seq: RecordSeq(42),
            bits: (1u64 << 0) | (1u64 << 17) | (1u64 << 63),
        };
        let mut encoded = [0; RecordAck::ENCODED_LEN];
        ack.encode_into(&mut encoded);

        assert_eq!(RecordAck::decode(&encoded).unwrap(), ack);
    }

    #[test]
    fn contains_matches_bit_membership() {
        let ack = RecordAck {
            base_seq: RecordSeq(100),
            bits: (1u64 << 0) | (1u64 << 5) | (1u64 << 63),
        };

        assert!(ack.contains(100));
        assert!(ack.contains(105));
        assert!(ack.contains(163));
        assert!(!ack.contains(99));
        assert!(!ack.contains(101));
        assert!(!ack.contains(164));
    }
}
