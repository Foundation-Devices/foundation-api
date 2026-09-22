use ql_codec::{Decode, Reader};

use crate::{Header, CHUNK_DATA_SIZE, HEADER_SIZE, MAX_RECORD_SIZE};

#[derive(Debug)]
pub enum ReceiveError {
    HeaderTooSmall,
    EmptyRecord,
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
            Self::EmptyRecord => f.write_str("record is empty"),
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

#[derive(Debug, Default)]
pub struct Dechunker {
    sequence: Option<u16>,
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
        let mut reader = Reader::new(data);
        let header = Header::decode(&mut reader).map_err(|_| ReceiveError::HeaderTooSmall)?;
        let record_len = header.record_len as usize;
        if record_len == 0 {
            return Err(ReceiveError::EmptyRecord);
        }
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
        match self.sequence {
            None => self.start(sequence, record_len),
            Some(current) if current == sequence => {
                if self.record_len != record_len {
                    return Err(ReceiveError::LengthChanged {
                        expected: self.record_len,
                        actual: record_len,
                    });
                }
            }
            Some(_) if header.index == 0 => self.start(sequence, record_len),
            Some(current) if sequence.wrapping_sub(current) < 1 << 15 => {
                self.start(sequence, record_len);
            }
            Some(current) => {
                return Err(ReceiveError::StaleSequence {
                    expected: current,
                    actual: sequence,
                });
            }
        }

        let index = header.index as usize;
        // split the chunk index into its bitmap word and bit offset
        let word = index / u64::BITS as usize;
        let bit = 1 << (index % u64::BITS as usize);
        if self.received[word] & bit == 0 {
            let start = index * CHUNK_DATA_SIZE;
            self.data[start..start + len].copy_from_slice(&payload[..len]);
            self.received[word] |= bit;
            self.received_count += 1;
        }

        if self.received_count == self.record_len.div_ceil(CHUNK_DATA_SIZE) {
            self.sequence = None;
            self.received.clear();
            self.received_count = 0;
            self.record_len = 0;
            return Ok(Some(std::mem::take(&mut self.data)));
        }
        Ok(None)
    }

    pub fn progress(&self) -> f32 {
        let total = self.record_len.div_ceil(CHUNK_DATA_SIZE);
        if total == 0 {
            0.0
        } else {
            self.received_count as f32 / total as f32
        }
    }

    fn start(&mut self, sequence: u16, record_len: usize) {
        let chunks = record_len.div_ceil(CHUNK_DATA_SIZE);
        self.sequence = Some(sequence);
        self.record_len = record_len;
        self.received.clear();
        self.received.resize(chunks.div_ceil(u64::BITS as usize), 0);
        self.received_count = 0;
        self.data.clear();
        self.data.resize(record_len, 0);
    }
}
