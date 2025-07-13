use consts::APP_MTU;
use rand::Rng;

#[cfg(test)]
mod tests;

const HEADER_SIZE: usize = std::mem::size_of::<Header>();
const CHUNK_DATA_SIZE: usize = APP_MTU - HEADER_SIZE;

#[derive(Debug, Clone, Copy)]
struct Header {
    message_id: u16,
    index: u16,
    total_chunks: u16,
    data_len: u8,
}

impl Header {
    fn write_bytes(&self, bytes: &mut [u8]) {
        bytes[0..2].copy_from_slice(&self.message_id.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.index.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.total_chunks.to_be_bytes());
        bytes[6] = self.data_len;
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_SIZE {
            return None;
        }
        let message_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let index = u16::from_be_bytes([bytes[2], bytes[3]]);
        let total_chunks = u16::from_be_bytes([bytes[4], bytes[5]]);
        let data_len = bytes[6];
        Some(Self {
            message_id,
            index,
            total_chunks,
            data_len,
        })
    }
}

pub struct Chunker<'a> {
    data: &'a [u8],
    message_id: u16,
    current_index: u16,
    total_chunks: u16,
}

impl<'a> Iterator for Chunker<'a> {
    type Item = [u8; APP_MTU];

    fn next(&mut self) -> Option<Self::Item> {
        let start_idx = self.current_index as usize * CHUNK_DATA_SIZE;
        if start_idx >= self.data.len() {
            return None;
        }

        let end_idx = (start_idx + CHUNK_DATA_SIZE).min(self.data.len());
        let chunk_data = &self.data[start_idx..end_idx];

        let header = Header {
            message_id: self.message_id,
            index: self.current_index,
            total_chunks: self.total_chunks,
            data_len: chunk_data.len() as u8,
        };

        let mut buffer = [0u8; APP_MTU];
        header.write_bytes(&mut buffer[..HEADER_SIZE]);
        buffer[HEADER_SIZE..HEADER_SIZE + chunk_data.len()].copy_from_slice(chunk_data);
        self.current_index += 1;

        Some(buffer)
    }
}

pub fn chunk(data: &[u8]) -> Chunker<'_> {
    let message_id = rand::rng().random::<u16>();
    let total_chunks = data.len().div_ceil(CHUNK_DATA_SIZE) as u16;

    Chunker {
        data,
        message_id,
        current_index: 0,
        total_chunks,
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum DecodeError {
    ChunkTooSmall { size: usize },
    InvalidHeader,
    WrongMessageId { expected: u16, received: u16 },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::ChunkTooSmall { size } => write!(f, "Packet too small: {size} bytes"),
            DecodeError::InvalidHeader => write!(f, "Invalid header"),
            DecodeError::WrongMessageId { expected, received } => {
                write!(
                    f,
                    "Wrong message ID: expected {expected}, received {received}"
                )
            }
        }
    }
}

impl std::error::Error for DecodeError {}

#[derive(Clone, Copy)]
struct Chunk {
    data: [u8; CHUNK_DATA_SIZE],
    len: u8,
}

impl Chunk {
    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

pub struct Dechunker {
    chunks: Vec<Option<Chunk>>,
    message_id: Option<u16>,
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
            message_id: None,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.message_id.is_some() && self.chunks.iter().all(|c| c.is_some())
    }

    pub fn clear(&mut self) {
        self.chunks.clear();
        self.message_id = None;
    }

    pub fn progress(&self) -> f32 {
        if self.chunks.len() == 0 {
            return 0.0;
        }
        let received = self.chunks.iter().filter(|c| c.is_some()).count();
        received as f32 / self.chunks.len() as f32
    }

    pub fn receive(&mut self, data: &[u8]) -> Result<(), DecodeError> {
        let Some((header_data, chunk_data)) = data.split_at_checked(HEADER_SIZE) else {
            return Err(DecodeError::ChunkTooSmall { size: data.len() });
        };

        let header = Header::from_bytes(header_data).ok_or(DecodeError::InvalidHeader)?;

        match self.message_id {
            None => {
                self.message_id = Some(header.message_id);
                self.chunks.resize(header.total_chunks as usize, None);
            }
            Some(id) if id != header.message_id => {
                return Err(DecodeError::WrongMessageId {
                    expected: id,
                    received: header.message_id,
                });
            }
            _ => {}
        }

        let data_len = header.data_len as usize;

        // store chunk if not already received
        // should this be an error?
        if self.chunks[header.index as usize].is_none() {
            let mut data = [0u8; CHUNK_DATA_SIZE];
            data[..data_len].copy_from_slice(&chunk_data[..data_len]);
            self.chunks[header.index as usize] = Some(Chunk {
                data,
                len: data_len as u8,
            });
        }

        Ok(())
    }

    pub fn message_id(&self) -> Option<u16> {
        self.message_id
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
