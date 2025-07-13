use crate::{Header, CHUNK_DATA_SIZE, HEADER_SIZE};

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("Packet too small: {size} bytes")]
    ChunkTooSmall { size: usize },
    #[error("Invalid header")]
    InvalidHeader,
}

#[derive(Debug, thiserror::Error)]
pub enum PushChunkError {
    #[error("wrong message id: expected {expected}, actual {actual}")]
    WrongMessageId { expected: u16, actual: u16 },
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Push(#[from] PushChunkError),
}

#[derive(Clone, Copy)]
pub struct Chunk {
    pub header: Header,
    pub chunk: [u8; CHUNK_DATA_SIZE],
}

impl Chunk {
    pub fn data(&self) -> &[u8] {
        &self.chunk[..self.header.data_len as usize]
    }
}

impl Chunk {
    pub fn new(header: Header, chunk: [u8; CHUNK_DATA_SIZE]) -> Self {
        Self { header, chunk }
    }
}

impl Chunk {
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        let (header_data, chunk_data) = data
            .split_at_checked(HEADER_SIZE)
            .ok_or(DecodeError::ChunkTooSmall { size: data.len() })?;

        let header = Header::from_bytes(header_data).ok_or(DecodeError::InvalidHeader)?;

        let data_len = header.data_len as usize;
        let mut chunk_array = [0u8; CHUNK_DATA_SIZE];
        chunk_array[..data_len].copy_from_slice(&chunk_data[..data_len]);

        Ok(Chunk {
            header: *header,
            chunk: chunk_array,
        })
    }
}

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

#[derive(Clone)]
struct RawChunk {
    data: [u8; CHUNK_DATA_SIZE],
    len: u8,
}

impl RawChunk {
    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

impl Default for Dechunker {
    fn default() -> Self {
        Self::new()
    }
}

impl Dechunker {
    pub fn new() -> Self {
        Self {
            chunks: Vec::new(),
            info: None,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.info
            .map(|info| info.chunks_received == info.total_chunks)
            .unwrap_or(false)
    }

    pub fn clear(&mut self) {
        self.chunks.clear();
        self.info = None;
    }

    pub fn progress(&self) -> f32 {
        self.info
            .map(|info| info.chunks_received as f32 / info.total_chunks as f32)
            .unwrap_or(0.0)
    }

    pub fn push_chunk(&mut self, chunk: Chunk) -> Result<(), PushChunkError> {
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
                return Err(PushChunkError::WrongMessageId {
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

            // Increment chunks_received count
            if let Some(ref mut info) = self.info {
                info.chunks_received += 1;
            }
        }

        Ok(())
    }

    pub fn receive(&mut self, data: &[u8]) -> Result<(), ReceiveError> {
        let chunk_with_header = Chunk::parse(data)?;
        self.push_chunk(chunk_with_header)?;
        Ok(())
    }

    pub fn message_id(&self) -> Option<u16> {
        self.info.map(|info| info.message_id)
    }

    pub fn data(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        let mut result = Vec::with_capacity(
            self.chunks
                .iter()
                .map(|chunk| chunk.as_ref().unwrap().len as usize)
                .sum(),
        );

        for chunk in &self.chunks {
            // is_complete confirms we are done
            result.extend_from_slice(chunk.as_ref().unwrap().as_slice());
        }

        Some(result)
    }
}
