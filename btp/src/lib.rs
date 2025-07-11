use consts::APP_MTU;
use rand::Rng;

#[cfg(test)]
mod tests;

const HEADER_SIZE: usize = std::mem::size_of::<Header>();

#[derive(Debug, Clone, Copy)]
struct Header {
    message_id: u16,
    index: u16,
    total_chunks: u16,
    data_len: u8,
    is_last: bool,
}

impl Header {
    fn to_bytes(self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0; HEADER_SIZE];
        bytes[0..2].copy_from_slice(&self.message_id.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.index.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.total_chunks.to_be_bytes());
        bytes[6] = self.data_len;
        bytes[7] = if self.is_last { 1 } else { 0 };
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_SIZE {
            return None;
        }
        let message_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let index = u16::from_be_bytes([bytes[2], bytes[3]]);
        let total_chunks = u16::from_be_bytes([bytes[4], bytes[5]]);
        let data_len = bytes[6];
        let is_last = bytes[7] != 0;
        Some(Self {
            message_id,
            index,
            total_chunks,
            data_len,
            is_last,
        })
    }
}

pub struct Chunker<'a> {
    data: &'a [u8],
    message_id: u16,
    current_index: u16,
    total_chunks: u16,
    data_per_chunk: usize,
}

impl<'a> Iterator for Chunker<'a> {
    type Item = [u8; APP_MTU];

    fn next(&mut self) -> Option<Self::Item> {
        let start_idx = self.current_index as usize * self.data_per_chunk;
        if start_idx >= self.data.len() {
            return None;
        }

        let mut buffer = [0u8; APP_MTU];

        let end_idx = (start_idx + self.data_per_chunk).min(self.data.len());
        let chunk_data = &self.data[start_idx..end_idx];
        let is_last = end_idx >= self.data.len();

        let header = Header {
            message_id: self.message_id,
            index: self.current_index,
            total_chunks: self.total_chunks,
            data_len: chunk_data.len() as u8,
            is_last,
        };

        buffer[..HEADER_SIZE].copy_from_slice(&header.to_bytes());
        buffer[HEADER_SIZE..HEADER_SIZE + chunk_data.len()].copy_from_slice(chunk_data);
        self.current_index += 1;

        Some(buffer)
    }
}

pub fn chunk(data: &[u8]) -> Chunker<'_> {
    let message_id = rand::rng().random::<u16>();
    let data_per_chunk = APP_MTU - HEADER_SIZE;
    let total_chunks = data.len().div_ceil(data_per_chunk) as u16;

    Chunker {
        data,
        message_id,
        current_index: 0,
        total_chunks,
        data_per_chunk,
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum DecodeError {
    PacketTooSmall { size: usize },
    InvalidHeader,
    WrongMessageId { expected: u16, received: u16 },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::PacketTooSmall { size } => write!(f, "Packet too small: {size} bytes"),
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

const CHUNK_DATA_SIZE: usize = APP_MTU - HEADER_SIZE;

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
    is_complete: bool,
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
            is_complete: false,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.is_complete
    }

    pub fn clear(&mut self) {
        self.chunks.clear();
        self.message_id = None;
        self.is_complete = false;
    }

    pub fn progress(&self) -> f32 {
        if self.chunks.len() == 0 {
            return 0.0;
        }
        let received = self.chunks.iter().filter(|c| c.is_some()).count();
        received as f32 / self.chunks.len() as f32
    }

    pub fn receive(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, DecodeError> {
        let Some((header_data, chunk_data)) = data.split_at_checked(HEADER_SIZE) else {
            return Err(DecodeError::PacketTooSmall { size: data.len() });
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

        if header.is_last {
            self.is_complete = true;
        }

        // attempt to complete the message
        if self.is_complete {
            let data = self.data();
            return Ok(data);
        }

        Ok(None)
    }

    pub fn message_id(&self) -> Option<u16> {
        self.message_id
    }

    pub fn data(&self) -> Option<Vec<u8>> {
        if !self.is_complete {
            return None;
        }

        let mut result = Vec::new();
        for chunk in &self.chunks {
            match chunk {
                Some(chunk) => result.extend_from_slice(chunk.as_slice()),
                None => return None,
            }
        }

        Some(result)
    }
}
