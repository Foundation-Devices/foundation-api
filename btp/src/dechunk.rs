use crate::{Header, CHUNK_DATA_SIZE, HEADER_SIZE};

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("chunk too small, expected at least {}", HEADER_SIZE)]
    HeaderTooSmall,

    #[error("invalid chunk header")]
    InvalidHeader,

    #[error("chunk data too small: header claims {expected} bytes, but only {actual} available")]
    ChunkTooSmall { expected: usize, actual: usize },

    #[error("invalid chunk index: {index} >= {total_chunks}")]
    InvalidChunkIndex { index: u16, total_chunks: u16 },

    #[error("chunk data length exceeds maximum chunk size {}", CHUNK_DATA_SIZE)]
    ChunkTooLarge,
}

#[derive(Debug, thiserror::Error)]
#[error("wrong message id: expected {expected}, actual {actual}")]
pub struct MessageIdError {
    expected: u16,
    actual: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    MessageId(#[from] MessageIdError),
}

#[derive(Clone, Copy)]
pub struct Chunk {
    pub header: Header,
    pub chunk: [u8; CHUNK_DATA_SIZE],
}

impl Chunk {
    /// Returns chunk data as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.chunk[..self.header.data_len as usize]
    }

    /// decodes raw bytes into a chunk
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let (header_data, chunk_data) = data
            .split_at_checked(HEADER_SIZE)
            .ok_or(DecodeError::HeaderTooSmall)?;

        let header = Header::from_bytes(header_data).ok_or(DecodeError::InvalidHeader)?;

        if header.index >= header.total_chunks {
            return Err(DecodeError::InvalidChunkIndex {
                index: header.index,
                total_chunks: header.total_chunks,
            });
        }

        let data_len = header.data_len as usize;

        if data_len > CHUNK_DATA_SIZE {
            return Err(DecodeError::ChunkTooLarge);
        }

        if chunk_data.len() < data_len {
            return Err(DecodeError::ChunkTooSmall {
                expected: data_len,
                actual: chunk_data.len(),
            });
        }

        let mut chunk = [0u8; CHUNK_DATA_SIZE];
        chunk[..data_len].copy_from_slice(&chunk_data[..data_len]);

        Ok(Chunk {
            header: *header,
            chunk,
        })
    }
}

#[derive(Debug, Default)]
pub struct Dechunker {
    chunks: Vec<Option<RawChunk>>,
    info: Option<MessageInfo>,
}

#[derive(Debug, Clone, Copy)]
struct MessageInfo {
    message_id: u16,
    total_chunks: u16,
    chunks_received: u16,
}

#[derive(Debug, Clone)]
pub(crate) struct RawChunk {
    data: [u8; CHUNK_DATA_SIZE],
    len: u8,
}

impl RawChunk {
    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

impl Dechunker {
    /// Creates a new dechunker
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if all chunks received
    pub fn is_complete(&self) -> bool {
        self.info
            .map(|info| info.chunks_received == info.total_chunks)
            .unwrap_or(false)
    }

    /// Clears all chunks and resets state
    pub fn clear(&mut self) {
        self.chunks.clear();
        self.info = None;
    }

    /// Returns progress as fraction (0.0 to 1.0)
    pub fn progress(&self) -> f32 {
        self.info
            .map(|info| info.chunks_received as f32 / info.total_chunks as f32)
            .unwrap_or(0.0)
    }

    /// Inserts a chunk. Use this for multiple concurrent messages.
    /// First decode with [`Chunk::decode()`], lookup decoder by message ID, then insert.
    pub fn insert_chunk(&mut self, chunk: Chunk) -> Result<(), MessageIdError> {
        let header = &chunk.header;

        match self.info {
            None => {
                self.info = Some(MessageInfo {
                    message_id: header.message_id,
                    total_chunks: header.total_chunks,
                    chunks_received: 0,
                });
                self.chunks.resize(header.total_chunks as usize, None);
            }
            Some(info) if info.message_id != header.message_id => {
                return Err(MessageIdError {
                    expected: info.message_id,
                    actual: header.message_id,
                });
            }
            _ => {}
        }

        // store chunk if not already received
        if self.chunks[header.index as usize].is_none() {
            self.chunks[header.index as usize] = Some(RawChunk {
                len: header.data_len,
                data: chunk.chunk,
            });

            if let Some(ref mut info) = self.info {
                info.chunks_received += 1;
            }
        }

        Ok(())
    }

    /// Decodes and inserts raw chunk data. Use this for single message at a time.
    /// For multiple concurrent messages, use [`Chunk::parse()`] then [`Dechunker::insert_chunk()`].
    pub fn receive(&mut self, data: &[u8]) -> Result<(), ReceiveError> {
        let chunk_with_header = Chunk::decode(data)?;
        self.insert_chunk(chunk_with_header)?;
        Ok(())
    }

    /// Returns the message ID if we've received a chunk
    pub fn message_id(&self) -> Option<u16> {
        self.info.map(|info| info.message_id)
    }

    /// Returns reassembled data if complete
    pub fn data(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        // unwraps are now ok

        let mut result = Vec::with_capacity(
            self.chunks
                .iter()
                .map(|chunk| chunk.as_ref().unwrap().len as usize)
                .sum(),
        );

        for chunk in &self.chunks {
            result.extend_from_slice(chunk.as_ref().unwrap().as_slice());
        }

        Some(result)
    }
}

pub struct MasterDechunker<const N: usize> {
    dechunkers: [Option<DechunkerSlot>; N],
    counter: u64,
}

#[derive(Debug)]
struct DechunkerSlot {
    dechunker: Dechunker,
    last_used: u64,
}

impl<const N: usize> Default for MasterDechunker<N> {
    fn default() -> Self {
        Self {
            dechunkers: std::array::from_fn(|_| None),
            counter: 0,
        }
    }
}

impl<const N: usize> MasterDechunker<N> {
    pub fn insert_chunk(&mut self, chunk: Chunk) -> Option<Vec<u8>> {
        let message_id = chunk.header.message_id;

        for decoder_slot in &mut self.dechunkers {
            if let Some(ref mut slot) = decoder_slot {
                if slot.dechunker.message_id() == Some(message_id) {
                    self.counter += 1;
                    slot.last_used = self.counter;
                    slot.dechunker.insert_chunk(chunk).unwrap();

                    return if slot.dechunker.is_complete() {
                        decoder_slot.take().unwrap().dechunker.data()
                    } else {
                        None
                    };
                }
            }
        }

        let target_slot =
            if let Some(empty_slot) = self.dechunkers.iter_mut().find(|slot| slot.is_none()) {
                empty_slot
            } else {
                self.dechunkers
                    .iter_mut()
                    .min_by_key(|d| d.as_ref().map(|d| d.last_used))
                    .expect("not empty")
            };

        let mut decoder = Dechunker::new();
        decoder.insert_chunk(chunk).unwrap();

        if decoder.is_complete() {
            decoder.data()
        } else {
            self.counter += 1;
            *target_slot = Some(DechunkerSlot {
                dechunker: decoder,
                last_used: self.counter,
            });
            None
        }
    }

    pub fn get_dechunker(&self, msg_id: u16) -> Option<&Dechunker> {
        self.dechunkers
            .iter()
            .filter_map(|d| d.as_ref())
            .find(|d| d.dechunker.info.map(|m| m.message_id) == Some(msg_id))
            .map(|d| &d.dechunker)
    }
}
