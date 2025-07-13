use consts::APP_MTU;

use crate::{Header, CHUNK_DATA_SIZE, HEADER_SIZE};

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

        let header = Header::new(
            self.message_id,
            self.current_index,
            self.total_chunks,
            chunk_data.len() as u8,
        );

        let mut buffer = [0u8; APP_MTU];
        buffer[..HEADER_SIZE].copy_from_slice(header.as_bytes());
        buffer[HEADER_SIZE..HEADER_SIZE + chunk_data.len()].copy_from_slice(chunk_data);
        self.current_index += 1;

        Some(buffer)
    }
}

pub fn chunk(data: &[u8]) -> Chunker<'_> {
    let message_id = rand::Rng::random::<u16>(&mut rand::rng());
    let total_chunks = data.len().div_ceil(CHUNK_DATA_SIZE) as u16;

    Chunker {
        data,
        message_id,
        current_index: 0,
        total_chunks,
    }
}
