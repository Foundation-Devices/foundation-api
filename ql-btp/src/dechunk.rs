use ql_codec::{Decode, Reader};

use crate::{
    packet_version, Header, Version, CHUNK_DATA_SIZE, HEADER_SIZE, MAX_RECORD_SIZE, RECORD_LEN_MASK,
};

#[derive(Debug)]
pub enum ReceiveError {
    HeaderTooSmall,
    UnsupportedVersion { tag: u8 },
    RecordTooLarge { actual: usize, maximum: usize },
    InvalidChunkIndex { index: u16, total_chunks: usize },
    ChunkTooSmall { expected: usize, actual: usize },
    LengthChanged { expected: usize, actual: usize },
    StaleSequence { expected: u16, actual: u16 },
}

impl std::fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderTooSmall => {
                write!(
                    f,
                    "chunk is too small, expected at least {HEADER_SIZE} bytes"
                )
            }
            Self::UnsupportedVersion { tag } => {
                write!(f, "unsupported BTP version tag 0x{tag:02x}")
            }
            Self::RecordTooLarge { actual, maximum } => {
                write!(f, "record is too large: {actual} bytes exceeds {maximum}")
            }
            Self::InvalidChunkIndex {
                index,
                total_chunks,
            } => write!(f, "invalid chunk index: {index} >= {total_chunks}"),
            Self::ChunkTooSmall { expected, actual } => write!(
                f,
                "chunk data is too small: expected {expected} bytes, received {actual}"
            ),
            Self::LengthChanged { expected, actual } => {
                write!(f, "record length changed from {expected} to {actual}")
            }
            Self::StaleSequence { expected, actual } => {
                write!(f, "stale sequence {actual}, current sequence is {expected}")
            }
        }
    }
}

impl std::error::Error for ReceiveError {}

/// two records are stored at a time to support out of order packets between adjacent records
#[derive(Debug, Default)]
pub struct Dechunker {
    records: [Option<Record>; 2],
}

#[derive(Debug)]
struct Record {
    sequence: u16,
    record_len: usize,
    // one bit per chunk, set after that chunk is copied into data
    received: Vec<u64>,
    received_count: usize,
    data: Vec<u8>,
}

impl Dechunker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn receive(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, ReceiveError> {
        if data.len() < HEADER_SIZE {
            return Err(ReceiveError::HeaderTooSmall);
        }
        if packet_version(data) != Some(Version::V2) {
            return Err(ReceiveError::UnsupportedVersion {
                tag: data[HEADER_SIZE - 1],
            });
        }
        let mut reader = Reader::new(data);
        let header = Header::decode(&mut reader).map_err(|_| ReceiveError::HeaderTooSmall)?;
        let record_len = (header.tagged_record_len & RECORD_LEN_MASK) as usize;
        if record_len > MAX_RECORD_SIZE {
            return Err(ReceiveError::RecordTooLarge {
                actual: record_len,
                maximum: MAX_RECORD_SIZE,
            });
        }

        let total_chunks = record_len.div_ceil(CHUNK_DATA_SIZE);
        if header.index as usize >= total_chunks {
            return Err(ReceiveError::InvalidChunkIndex {
                index: header.index,
                total_chunks,
            });
        }

        let start = header.index as usize * CHUNK_DATA_SIZE;
        let len = CHUNK_DATA_SIZE.min(record_len - start);
        let payload = reader.take_all();
        if payload.len() < len {
            return Err(ReceiveError::ChunkTooSmall {
                expected: len,
                actual: payload.len(),
            });
        }

        let sequence = header.sequence;
        let target = match &self.records {
            [Some(first), _] if first.sequence == sequence => 0,
            [_, Some(second)] if second.sequence == sequence => 1,
            [None, _] => 0,
            [_, None] => 1,
            [Some(first), Some(second)] => {
                // wrapping distance makes 0 newer than u16::MAX
                // only an exact half-cycle is ambiguous
                let is_newer = |sequence: u16, current: u16| {
                    let distance = sequence.wrapping_sub(current);
                    distance != 0 && distance < 1 << 15
                };
                let (newest, newest_sequence) = if is_newer(second.sequence, first.sequence) {
                    (1, second.sequence)
                } else {
                    (0, first.sequence)
                };
                if !is_newer(sequence, newest_sequence) {
                    return Err(ReceiveError::StaleSequence {
                        expected: newest_sequence,
                        actual: sequence,
                    });
                }
                1 - newest
            }
        };

        if let Some(record) = &self.records[target] {
            if record.sequence == sequence && record.record_len != record_len {
                return Err(ReceiveError::LengthChanged {
                    expected: record.record_len,
                    actual: record_len,
                });
            }
            if record.sequence != sequence {
                self.records[target] = None;
            }
        }
        let record = self.records[target].get_or_insert_with(|| Record {
            sequence,
            record_len,
            received: vec![0; total_chunks.div_ceil(u64::BITS as usize)],
            received_count: 0,
            data: vec![0; record_len],
        });

        let index = header.index as usize;
        // split the chunk index into its bitmap word and bit offset
        let word = index / u64::BITS as usize;
        let bit = 1 << (index % u64::BITS as usize);
        if record.received[word] & bit == 0 {
            let start = index * CHUNK_DATA_SIZE;
            record.data[start..start + len].copy_from_slice(&payload[..len]);
            record.received[word] |= bit;
            record.received_count += 1;
        }

        if record.received_count == total_chunks {
            return Ok(self.records[target].take().map(|record| record.data));
        }
        Ok(None)
    }
}
