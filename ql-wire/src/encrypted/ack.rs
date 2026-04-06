use crate::{codec, ByteSlice, RecordSeq, WireError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordAck {
    pub base_seq: RecordSeq,
    pub bits: u64,
}

impl RecordAck {
    pub const BITMAP_BITS: usize = u64::BITS as usize;

    pub fn contains(&self, seq: u64) -> bool {
        if seq < self.base_seq.into_inner() {
            return false;
        }

        let offset = seq - self.base_seq.into_inner();
        if offset >= Self::BITMAP_BITS as u64 {
            return false;
        }

        (self.bits & (1u64 << offset)) != 0
    }

    pub fn wire_size(&self) -> usize {
        self.base_seq.encoded_len() + size_of::<u64>()
    }

    pub fn encode_into(&self, out: &mut [u8]) {
        assert!(out.len() >= self.wire_size());
        let out = codec::write_varint(out, self.base_seq.0);
        let _ = codec::write_u64(out, self.bits);
    }
}

impl<B: ByteSlice> codec::WireParse<B> for RecordAck {
    fn parse(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            base_seq: RecordSeq(reader.take_varint()?),
            bits: reader.take_u64()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::RecordAck;
    use crate::{RecordSeq, WireError, WireParse};

    #[test]
    fn encode_decode_round_trip() {
        let ack = RecordAck {
            base_seq: RecordSeq::from_u32(42),
            bits: (1u64 << 0) | (1u64 << 17) | (1u64 << 63),
        };
        let mut encoded = vec![0; ack.wire_size()];
        ack.encode_into(&mut encoded);

        assert_eq!(RecordAck::parse_bytes(encoded.as_slice()).unwrap(), ack);
    }

    #[test]
    fn contains_matches_bit_membership() {
        let ack = RecordAck {
            base_seq: RecordSeq::from_u32(100),
            bits: (1u64 << 0) | (1u64 << 5) | (1u64 << 63),
        };

        assert!(ack.contains(100));
        assert!(ack.contains(105));
        assert!(ack.contains(163));
        assert!(!ack.contains(99));
        assert!(!ack.contains(101));
        assert!(!ack.contains(164));
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        assert_eq!(
            RecordAck::parse_bytes(&[][..]),
            Err(WireError::InvalidPayload)
        );
        let encoded = vec![0; RecordSeq::from_u32(0).encoded_len() + size_of::<u64>()];
        assert_eq!(
            RecordAck::parse_bytes(&encoded[..encoded.len() - 1]),
            Err(WireError::InvalidPayload)
        );
    }
}
