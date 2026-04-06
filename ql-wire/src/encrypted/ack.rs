use crate::{codec, ByteSlice, RecordSeq, WireEncode, WireError};

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
}

impl WireEncode for RecordAck {
    fn encoded_len(&self) -> usize {
        self.base_seq.encoded_len() + size_of::<u64>()
    }

    fn encode<W: ::bytes::BufMut + ?Sized>(&self, out: &mut W) {
        self.base_seq.encode(out);
        self.bits.encode(out);
    }
}

impl<B: ByteSlice> codec::WireDecode<B> for RecordAck {
    fn decode(reader: &mut codec::Reader<B>) -> Result<Self, WireError> {
        Ok(Self {
            base_seq: reader.decode()?,
            bits: reader.decode()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::RecordAck;
    use crate::{RecordSeq, WireDecode, WireEncode, WireError};

    #[test]
    fn encode_decode_round_trip() {
        let ack = RecordAck {
            base_seq: RecordSeq::from_u32(42),
            bits: (1u64 << 0) | (1u64 << 17) | (1u64 << 63),
        };
        let encoded = ack.encode_vec();

        assert_eq!(RecordAck::decode_exact(encoded.as_slice()).unwrap(), ack);
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
            RecordAck::decode_exact(&[][..]),
            Err(WireError::InvalidPayload)
        );
        let encoded = vec![0; RecordSeq::from_u32(0).encoded_len() + size_of::<u64>()];
        assert_eq!(
            RecordAck::decode_exact(&encoded[..encoded.len() - 1]),
            Err(WireError::InvalidPayload)
        );
    }
}
