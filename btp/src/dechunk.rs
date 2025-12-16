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
#[error("message length: expected {expected}, actual {actual}")]
pub struct LengthMismatchError {
    message_id: u16,
    expected: u16,
    actual: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    MessageId(#[from] MessageIdError),
    #[error(transparent)]
    LengthMismatch(#[from] LengthMismatchError),
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

#[derive(Default)]
pub struct Dechunker {
    pub chunks: Vec<Option<RawChunk>>,
    pub info: Option<MessageInfo>,
}

impl std::fmt::Debug for Dechunker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dechunker")
            .field(
                "chunks",
                &self.chunks.iter().map(|c| if c.is_some() { 1 } else { 0 }),
            )
            .field("info", &self.info)
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MessageInfo {
    pub message_id: u16,
    pub total_chunks: u16,
    pub chunks_received: u16,
}

#[derive(Debug, Clone)]
pub struct RawChunk {
    pub data: [u8; CHUNK_DATA_SIZE],
    pub len: u8,
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
    /// First decode with [`Chunk::decode()`], lookup decoder by message ID,
    /// then insert.
    pub fn insert_chunk(&mut self, chunk: Chunk) -> Result<(), ReceiveError> {
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
                }
                .into());
            }
            Some(info) if info.total_chunks != header.total_chunks => {
                return Err(LengthMismatchError {
                    message_id: header.message_id,
                    expected: info.message_id,
                    actual: header.message_id,
                }
                .into());
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

    /// Decodes and inserts raw chunk data. Use this for single message at a
    /// time. For multiple concurrent messages, use [`Chunk::parse()`] then
    /// [`Dechunker::insert_chunk()`].
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

        let result = self
            .chunks
            .iter()
            .flat_map(|chunk| chunk.as_ref().unwrap().as_slice())
            .copied()
            .collect();

        Some(result)
    }
}

#[derive(Debug)]
pub struct MasterDechunker<const N: usize> {
    dechunkers: [Option<DechunkerSlot>; N],
    counter: u64,
}

#[derive(Debug)]
pub struct DechunkerSlot {
    pub dechunker: Dechunker,
    pub last_used: u64,
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
    pub fn dechunkers(&self) -> &[Option<DechunkerSlot>] {
        &self.dechunkers
    }

    pub fn insert_chunk(&mut self, chunk: Chunk) -> Option<Vec<u8>> {
        let (completed, _evicted) = self.insert_chunk_raw(chunk);
        completed
    }

    pub fn insert_chunk_raw(&mut self, chunk: Chunk) -> (Option<Vec<u8>>, Option<DechunkerSlot>) {
        let message_id = chunk.header.message_id;

        for decoder_slot in &mut self.dechunkers {
            if let Some(ref mut slot) = decoder_slot {
                if slot.dechunker.message_id() == Some(message_id) {
                    self.counter += 1;
                    slot.last_used = self.counter;
                    slot.dechunker.insert_chunk(chunk).unwrap();

                    return if slot.dechunker.is_complete() {
                        let completed = decoder_slot.take().unwrap().dechunker.data();
                        (completed, None)
                    } else {
                        (None, None)
                    };
                }
            }
        }

        let (target_slot, evicted) =
            if let Some(empty_slot) = self.dechunkers.iter_mut().find(|slot| slot.is_none()) {
                (empty_slot, None)
            } else {
                let slot = self
                    .dechunkers
                    .iter_mut()
                    .min_by_key(|d| d.as_ref().map(|d| d.last_used))
                    .expect("not empty");

                let evicted = slot.take();
                (slot, evicted)
            };

        let mut decoder = Dechunker::new();
        decoder.insert_chunk(chunk).unwrap();

        if decoder.is_complete() {
            (decoder.data(), evicted)
        } else {
            self.counter += 1;
            *target_slot = Some(DechunkerSlot {
                dechunker: decoder,
                last_used: self.counter,
            });
            (None, evicted)
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
